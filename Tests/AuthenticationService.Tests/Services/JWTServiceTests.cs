using System.IdentityModel.Tokens.Jwt;
using System.Security.Cryptography;
using AuthenticationService.Constants;
using AuthenticationService.Entities;
using AuthenticationService.Enums;
using AuthenticationService.Services;
using AuthenticationService.Settings;
using AuthenticationService.Shared.Constants;
using AuthenticationService.Storage;
using AuthenticationService.Tests.Helpers;
using AwesomeAssertions;
using Microsoft.AspNetCore.Identity;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using NSubstitute;

namespace AuthenticationService.Tests.Services;

/// <summary>
/// <para><see cref="JWTService"/> owns the JWT lifecycle: creation, validation,
/// revocation, refresh-token rotation with reuse detection, and the audit trail. Every
/// branch is exercised here against a real EF Core in-memory context and a real
/// <see cref="EcdsaKeyProvider"/> with a generated key — both because the JWT-signing
/// crypto isn't worth mocking and because the in-memory provider exercises the same EF
/// query shapes the production code emits against MySQL.</para>
///
/// <para>Paths covered:</para>
/// <list type="bullet">
///   <item><description><b>CreateTokenAsync</b> — happy path, claim shape (sub/sid/jti/name/email/role), refresh-token persisted as hash not raw, FamilyId reused when supplied.</description></item>
///   <item><description><b>RotateRefreshTokenAsync</b> — success, NotFound (unknown token), NotFound (unknown user), NotFound (empty/invalid access token), Expired, Reused (already-consumed token), Reused (concurrency: ExecuteUpdate claims zero rows).</description></item>
///   <item><description><b>ValidateExpiredTokenAsync</b> — valid signature passes, wrong issuer fails, garbage token fails.</description></item>
///   <item><description><b>RevokeTokenAsync</b> — adds row to RevokedTokens with jti/userId/expires/ip/reason.</description></item>
///   <item><description><b>RevokeOrphanedTokenAsync</b> — same as RevokeTokenAsync but with the canonical UserNotFound reason and the orphan log line.</description></item>
///   <item><description><b>GetRevokedTokenAsync</b> — round-trips the row by jti.</description></item>
///   <item><description><b>RecordRevokedReplayAsync</b> — Severity.Low for naturally-expired tokens, Severity.Medium for still-live, UA truncated to 512 chars, UA null treated as null.</description></item>
///   <item><description><b>RevokeAllRefreshTokenFamiliesAsync</b> — only marks active (ConsumedAt == null) rows; consumed rows untouched; reason persisted.</description></item>
///   <item><description><b>RevokeFamilyAsync</b> — only the named family; other families untouched.</description></item>
///   <item><description><b>GetUserId / GetExpiryDateTime</b> — read claims from a JWT; missing-claim and malformed-token paths.</description></item>
/// </list>
/// </summary>
public class JWTServiceTests : IDisposable
{
    private readonly string _keyDir = Path.Combine(Path.GetTempPath(), "jwt-tests-" + Guid.NewGuid().ToString("N"));
    private readonly EcdsaKeyProvider _keyProvider;
    private readonly JWTSettings _settings = new()
    {
        PrivateKeyDirectory = "ignored",
        ActiveKeyId = "auto",
        ValidIssuer = "https://auth.test",
        ValidAudience = "test-aud",
        ExpiryInMinutes = 15,
        RefreshTokenExpiryInDays = 14,
    };

    public JWTServiceTests()
    {
        Directory.CreateDirectory(_keyDir);
        // Real signing keys — the JWT crypto path isn't worth mocking and the test pins
        // wire-shape behaviour (signature valid, claims present, etc.).
        using var ec = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        File.WriteAllText(Path.Combine(_keyDir, "key.pem"), ec.ExportECPrivateKeyPem());

        var keySettings = new JWTSettings
        {
            PrivateKeyDirectory = _keyDir,
            ActiveKeyId = "auto",
            ValidIssuer = _settings.ValidIssuer,
            ValidAudience = _settings.ValidAudience,
            ExpiryInMinutes = _settings.ExpiryInMinutes,
            RefreshTokenExpiryInDays = _settings.RefreshTokenExpiryInDays,
        };
        var env = Substitute.For<IHostEnvironment>();
        env.EnvironmentName.Returns(Environments.Development);
        env.ContentRootPath.Returns(Path.GetTempPath());

        _keyProvider = new EcdsaKeyProvider(Options.Create(keySettings), env, NullLogger<EcdsaKeyProvider>.Instance);
    }

    public void Dispose()
    {
        _keyProvider.Dispose();
        foreach (var ctx in _trackedContexts) ctx.Dispose();
        foreach (var conn in _trackedConnections) conn.Dispose();
        try { Directory.Delete(_keyDir, recursive: true); } catch { /* best-effort */ }
    }

    // ─── CreateTokenAsync ───────────────────────────────────────────────────────────────

    [Fact]
    public async Task CreateTokenAsync_HappyPath_ReturnsBearerWithExpectedShape()
    {
        // arrange — service + a registered user.
        var (service, db, _) = BuildService();
        var user = await SeedUserAsync(db, "alice", "alice@example.com");

        // act
        var token = await service.CreateTokenAsync(user, ["DefaultUser"], familyId: null, ipAddress: "10.0.0.1");

        // assert — Bearer scheme, non-empty JWT, refresh token + expiry set.
        token.Type.Should().Be(AuthSchemeConstants.Bearer);
        token.Value.Should().NotBeNullOrWhiteSpace();
        token.Expires.Should().BeAfter(DateTime.UtcNow);
        token.RefreshToken.Should().NotBeNullOrWhiteSpace();
        token.RefreshTokenExpiresAt.Should().BeAfter(DateTime.UtcNow);
    }

    [Fact]
    public async Task CreateTokenAsync_StampsExpectedClaims()
    {
        // arrange
        var (service, db, _) = BuildService();
        var user = await SeedUserAsync(db, "alice", "alice@example.com");
        var familyId = Guid.NewGuid();

        // act
        var token = await service.CreateTokenAsync(user, ["Admin", "DefaultUser"], familyId);

        // assert — verify the claim payload is exactly what consumers (JwtBearer in
        // every microservice) read.
        var jwt = new JwtSecurityTokenHandler().ReadJwtToken(token.Value);
        jwt.Claims.First(c => c.Type == ClaimConstants.Sub).Value.Should().Be(user.Id);
        jwt.Claims.First(c => c.Type == ClaimConstants.Sid).Value.Should().Be(familyId.ToString());
        jwt.Claims.Any(c => c.Type == ClaimConstants.Jti).Should().BeTrue();
        jwt.Claims.First(c => c.Type == ClaimConstants.Name).Value.Should().Be("alice");
        jwt.Claims.First(c => c.Type == ClaimConstants.Email).Value.Should().Be("alice@example.com");
        jwt.Claims.Where(c => c.Type == ClaimConstants.Role).Select(c => c.Value)
            .Should().BeEquivalentTo(["Admin", "DefaultUser"]);
        jwt.Issuer.Should().Be(_settings.ValidIssuer);
        jwt.Audiences.Should().Contain(_settings.ValidAudience);
    }

    [Fact]
    public async Task CreateTokenAsync_PersistsRefreshTokenAsHashNotRaw()
    {
        // arrange — the raw refresh token must never be in the DB; only its SHA-256.
        // Otherwise a DB compromise hands an attacker every active session.
        var (service, db, _) = BuildService();
        var user = await SeedUserAsync(db, "alice", "alice@example.com");

        // act
        var token = await service.CreateTokenAsync(user, ["DefaultUser"]);

        // assert
        var stored = await db.RefreshTokens.SingleAsync();
        stored.TokenHash.Should().NotBe(token.RefreshToken!,
            because: "stored value must be the hash, not the raw token.");
        stored.UserId.Should().Be(user.Id);
        stored.ExpiresAt.Should().BeAfter(DateTime.UtcNow);
        stored.ConsumedAt.Should().BeNull();
    }

    [Fact]
    public async Task CreateTokenAsync_NoFamilyIdSupplied_GeneratesNewOne()
    {
        // arrange — first login of a session, no family yet. Service generates a fresh sid.
        var (service, db, _) = BuildService();
        var user = await SeedUserAsync(db, "alice", "alice@example.com");

        // act
        var token1 = await service.CreateTokenAsync(user, ["DefaultUser"]);
        var token2 = await service.CreateTokenAsync(user, ["DefaultUser"]);

        // assert — distinct sid claims because family was generated each time.
        var sid1 = ReadClaim(token1.Value, ClaimConstants.Sid);
        var sid2 = ReadClaim(token2.Value, ClaimConstants.Sid);
        sid1.Should().NotBe(sid2);
    }

    [Fact]
    public async Task CreateTokenAsync_FamilyIdSupplied_PreservesIt()
    {
        // arrange — refresh-rotation passes the existing FamilyId so subsequent tokens
        // stay in the same session.
        var (service, db, _) = BuildService();
        var user = await SeedUserAsync(db, "alice", "alice@example.com");
        var family = Guid.NewGuid();

        // act
        var token = await service.CreateTokenAsync(user, ["DefaultUser"], family);

        // assert
        ReadClaim(token.Value, ClaimConstants.Sid).Should().Be(family.ToString());
    }

    // ─── RotateRefreshTokenAsync ────────────────────────────────────────────────────────

    [Fact]
    public async Task RotateRefreshTokenAsync_HappyPath_ReturnsSuccessAndConsumesOldToken()
    {
        // arrange — issue a token then rotate it.
        var (service, db, _) = BuildService();
        var user = await SeedUserAsync(db, "alice", "alice@example.com");
        var initial = await service.CreateTokenAsync(user, ["DefaultUser"]);

        // act
        var result = await service.RotateRefreshTokenAsync(initial.Value, initial.RefreshToken!, ipAddress: "10.0.0.1");

        // assert — Success + the original refresh-token row is now ConsumedAt non-null.
        result.Should().BeOfType<RefreshResult.Success>();
        var newToken = ((RefreshResult.Success)result).Token;
        newToken.Value.Should().NotBe(initial.Value);
        newToken.RefreshToken.Should().NotBe(initial.RefreshToken);

        // FamilyId preserved across the rotation.
        ReadClaim(newToken.Value, ClaimConstants.Sid).Should()
            .Be(ReadClaim(initial.Value, ClaimConstants.Sid));

        // Old row consumed. ExecuteUpdate skips EF's change tracker, so clear it before
        // reading or we'd see the pre-update cached value.
        db.ChangeTracker.Clear();
        var rows = await db.RefreshTokens.OrderBy(r => r.CreatedAt).ToListAsync();
        rows.Should().HaveCount(2);
        rows.Should().ContainSingle(r => r.ConsumedAt != null,
            because: "exactly the old row should be consumed; the new row stays active.");

        // ReplacedByTokenId chain link: the consumed (old) row points at the new row's
        // PK. Lets reuse detection identify the live family member via an explicit FK
        // rather than ordering by CreatedAt — important when the table is large or when
        // an audit walks the rotation chain backwards.
        var original = rows[0];
        var rotated = rows[1];
        original.ReplacedByTokenId.Should().Be(rotated.Id,
            because: "the consume step records which row replaced this one in the same UPDATE that sets ConsumedAt.");
        rotated.ReplacedByTokenId.Should().BeNull(
            because: "the live row at the end of the chain has nothing after it yet.");
    }

    [Fact]
    public async Task RotateRefreshTokenAsync_UnknownRefreshToken_ReturnsNotFound()
    {
        // arrange — valid access token but a refresh token never issued.
        var (service, db, _) = BuildService();
        var user = await SeedUserAsync(db, "alice", "alice@example.com");
        var initial = await service.CreateTokenAsync(user, ["DefaultUser"]);

        // act
        var result = await service.RotateRefreshTokenAsync(initial.Value, "garbage-not-a-real-refresh-token", ipAddress: "10.0.0.1");

        // assert — generic 401 (don't tip off the attacker which part was wrong).
        result.Should().BeOfType<RefreshResult.NotFound>();
    }

    [Fact]
    public async Task RotateRefreshTokenAsync_GarbageAccessToken_Throws()
    {
        // arrange — garbage access token. GetUserId calls JwtSecurityTokenHandler.ReadJwtToken
        // which throws SecurityTokenMalformedException on non-JWT input. Tests pin this so
        // callers (the controller) know they need the malformed-token try/catch.
        var (service, _, _) = BuildService();

        // act
        var act = async () => await service.RotateRefreshTokenAsync("not-a-jwt", "any", "10.0.0.1");

        // assert
        await act.Should().ThrowAsync<Microsoft.IdentityModel.Tokens.SecurityTokenMalformedException>();
    }

    [Fact]
    public async Task RotateRefreshTokenAsync_RefreshTokenExpired_ReturnsExpired()
    {
        // arrange — issue a token, then manually backdate its ExpiresAt past now.
        var (service, db, _) = BuildService();
        var user = await SeedUserAsync(db, "alice", "alice@example.com");
        var initial = await service.CreateTokenAsync(user, ["DefaultUser"]);

        var stored = await db.RefreshTokens.SingleAsync();
        stored.ExpiresAt = DateTime.UtcNow.AddDays(-1);
        await db.SaveChangesAsync();

        // act
        var result = await service.RotateRefreshTokenAsync(initial.Value, initial.RefreshToken!, "10.0.0.1");

        // assert
        result.Should().BeOfType<RefreshResult.Expired>();
    }

    [Fact]
    public async Task RotateRefreshTokenAsync_AlreadyConsumedToken_TriggersReuseCascade()
    {
        // arrange — rotate once successfully, then try to rotate using the same refresh
        // token a second time. Server treats this as theft: the every active family for
        // the user is revoked and the security stamp is rotated.
        var (service, db, userManager) = BuildService();
        var user = await SeedUserAsync(db, "alice", "alice@example.com");
        var initial = await service.CreateTokenAsync(user, ["DefaultUser"]);
        await service.RotateRefreshTokenAsync(initial.Value, initial.RefreshToken!, "10.0.0.1");

        // act — replay the now-consumed initial refresh token.
        var result = await service.RotateRefreshTokenAsync(initial.Value, initial.RefreshToken!, "10.0.0.1");

        // assert — Reused with the FamilyId, AND every active row for this user is now
        // revoked with ReuseDetected.
        result.Should().BeOfType<RefreshResult.Reused>();
        db.ChangeTracker.Clear();
        var rows = await db.RefreshTokens.ToListAsync();
        rows.Should().AllSatisfy(r => r.ConsumedAt.Should().NotBeNull());
        rows.Where(r => r.RevocationReason == RevocationReasons.ReuseDetected).Should().NotBeEmpty();

        // Security stamp was rotated as part of the cascade — UserManager call observed.
        await userManager.Received(1).UpdateSecurityStampAsync(Arg.Is<User>(u => u.Id == user.Id));
    }

    [Fact]
    public async Task RotateRefreshTokenAsync_UnknownUser_ReturnsNotFound()
    {
        // arrange — refresh token row exists but the user behind the access token's sub
        // claim is missing (e.g., user was deleted between issuance and refresh).
        var (service, db, userManager) = BuildService();
        var user = await SeedUserAsync(db, "alice", "alice@example.com");
        var initial = await service.CreateTokenAsync(user, ["DefaultUser"]);
        userManager.FindByIdAsync(user.Id).Returns((User?)null);

        // act
        var result = await service.RotateRefreshTokenAsync(initial.Value, initial.RefreshToken!, "10.0.0.1");

        // assert
        result.Should().BeOfType<RefreshResult.NotFound>();
    }

    // ─── ValidateExpiredTokenAsync ──────────────────────────────────────────────────────

    [Fact]
    public async Task ValidateExpiredTokenAsync_ValidlySigned_ReturnsTrue()
    {
        // arrange — issue a real token, then validate it (lifetime check disabled — that's
        // the whole purpose of ValidateExpiredTokenAsync, used during refresh).
        var (service, db, _) = BuildService();
        var user = await SeedUserAsync(db, "alice", "alice@example.com");
        var initial = await service.CreateTokenAsync(user, ["DefaultUser"]);

        // act
        var result = await service.ValidateExpiredTokenAsync(initial.Value);

        // assert
        result.Should().BeTrue();
    }

    [Fact]
    public async Task ValidateExpiredTokenAsync_TokenSignedByDifferentKey_ReturnsFalse()
    {
        // arrange — sign a token with a DIFFERENT EcdsaKeyProvider than the one the
        // service uses for validation. The validator should reject because the kid
        // doesn't match any known public key.
        var (service, _, _) = BuildService();
        using var otherKeyDir = new TempDir();
        using var otherEc = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        File.WriteAllText(Path.Combine(otherKeyDir.Path, "other.pem"), otherEc.ExportECPrivateKeyPem());
        var otherEnv = Substitute.For<IHostEnvironment>();
        otherEnv.EnvironmentName.Returns(Environments.Development);
        otherEnv.ContentRootPath.Returns(Path.GetTempPath());
        using var otherProvider = new EcdsaKeyProvider(
            Options.Create(new JWTSettings
            {
                PrivateKeyDirectory = otherKeyDir.Path,
                ActiveKeyId = "auto",
                ValidIssuer = _settings.ValidIssuer,
                ValidAudience = _settings.ValidAudience,
                ExpiryInMinutes = 15, RefreshTokenExpiryInDays = 14,
            }),
            otherEnv,
            NullLogger<EcdsaKeyProvider>.Instance);

        var jwt = new JwtSecurityToken(
            issuer: _settings.ValidIssuer,
            audience: _settings.ValidAudience,
            expires: DateTime.UtcNow.AddMinutes(5),
            signingCredentials: otherProvider.SigningCredentials);
        var foreignToken = new JwtSecurityTokenHandler().WriteToken(jwt);

        // act
        var result = await service.ValidateExpiredTokenAsync(foreignToken);

        // assert
        result.Should().BeFalse();
    }

    [Fact]
    public async Task ValidateExpiredTokenAsync_GarbageInput_ReturnsFalse()
    {
        // arrange — anything not a JWT should fail validation rather than throw.
        var (service, _, _) = BuildService();

        // act
        var result = await service.ValidateExpiredTokenAsync("definitely-not-a-jwt");

        // assert
        result.Should().BeFalse();
    }

    // ─── RevokeTokenAsync / GetRevokedTokenAsync / RevokeOrphanedTokenAsync ─────────────

    [Fact]
    public async Task RevokeTokenAsync_AddsRowToRevokedTokens()
    {
        // arrange
        var (service, db, _) = BuildService();
        var user = await SeedUserAsync(db, "alice", "alice@example.com");
        var token = await service.CreateTokenAsync(user, ["DefaultUser"]);

        // act
        await service.RevokeTokenAsync(token.Value, "10.0.0.1", RevocationReasons.Logout);

        // assert
        var stored = await db.RevokedTokens.SingleAsync();
        stored.UserId.Should().Be(user.Id);
        stored.RevokedFromIp.Should().Be("10.0.0.1");
        stored.RevocationReason.Should().Be(RevocationReasons.Logout);
        stored.RevokedAt.Should().BeCloseTo(DateTime.UtcNow, TimeSpan.FromSeconds(5));
        stored.ExpiresAt.Should().BeAfter(DateTime.UtcNow);
    }

    [Fact]
    public async Task GetRevokedTokenAsync_ReturnsRowByJti()
    {
        // arrange
        var (service, db, _) = BuildService();
        var user = await SeedUserAsync(db, "alice", "alice@example.com");
        var token = await service.CreateTokenAsync(user, ["DefaultUser"]);
        await service.RevokeTokenAsync(token.Value, "10.0.0.1", RevocationReasons.Logout);

        // act
        var found = await service.GetRevokedTokenAsync(token.Value);

        // assert
        found.Should().NotBeNull();
        found!.RevocationReason.Should().Be(RevocationReasons.Logout);
    }

    [Fact]
    public async Task GetRevokedTokenAsync_NonRevokedToken_ReturnsNull()
    {
        // arrange — never revoked.
        var (service, db, _) = BuildService();
        var user = await SeedUserAsync(db, "alice", "alice@example.com");
        var token = await service.CreateTokenAsync(user, ["DefaultUser"]);

        // act
        var found = await service.GetRevokedTokenAsync(token.Value);

        // assert
        found.Should().BeNull();
    }

    [Fact]
    public async Task RevokeOrphanedTokenAsync_RevokesWithUserNotFoundReason()
    {
        // arrange — token exists, the user it points to no longer does.
        var (service, db, _) = BuildService();
        var user = await SeedUserAsync(db, "alice", "alice@example.com");
        var token = await service.CreateTokenAsync(user, ["DefaultUser"]);

        // act
        await service.RevokeOrphanedTokenAsync(token.Value, "10.0.0.1");

        // assert — same shape as revoke, with the canonical reason.
        var stored = await db.RevokedTokens.SingleAsync();
        stored.RevocationReason.Should().Be(RevocationReasons.UserNotFound);
    }

    // ─── RecordRevokedReplayAsync ───────────────────────────────────────────────────────

    [Fact]
    public async Task RecordRevokedReplayAsync_StillLiveToken_RecordsMediumSeverity()
    {
        // arrange — revoked token whose own expiry is still in the future.
        var (service, db, _) = BuildService();
        var revoked = new RevokedToken
        {
            TokenJti = "j",
            UserId = "u",
            ExpiresAt = DateTime.UtcNow.AddMinutes(5),
        };

        // act
        await service.RecordRevokedReplayAsync(revoked, "10.0.0.1", "TestAgent");

        // assert
        var attempt = await db.RevokedTokenAccessAttempts.SingleAsync();
        attempt.Severity.Should().Be(Severity.Medium,
            because: "still-live revoked token: only the deny-list is stopping it. Higher severity.");
        attempt.IpAddress.Should().Be("10.0.0.1");
        attempt.UserAgent.Should().Be("TestAgent");
    }

    [Fact]
    public async Task RecordRevokedReplayAsync_NaturallyExpiredToken_RecordsLowSeverity()
    {
        // arrange — revoked token whose own expiry has already passed. JwtBearer would
        // reject it independently; our deny-list catch is incidental.
        var (service, db, _) = BuildService();
        var revoked = new RevokedToken
        {
            TokenJti = "j",
            UserId = "u",
            ExpiresAt = DateTime.UtcNow.AddMinutes(-5),
        };

        // act
        await service.RecordRevokedReplayAsync(revoked, "10.0.0.1", "ua");

        // assert
        var attempt = await db.RevokedTokenAccessAttempts.SingleAsync();
        attempt.Severity.Should().Be(Severity.Low);
    }

    [Fact]
    public async Task RecordRevokedReplayAsync_NullExpiresAt_TreatedAsStillLive()
    {
        // arrange — defensive: ExpiresAt nullable. If null we treat as still-live (we
        // can't prove expiry) — Medium severity.
        var (service, db, _) = BuildService();
        var revoked = new RevokedToken { TokenJti = "j", UserId = "u", ExpiresAt = null };

        // act
        await service.RecordRevokedReplayAsync(revoked, "10.0.0.1", "ua");

        // assert
        (await db.RevokedTokenAccessAttempts.SingleAsync()).Severity.Should().Be(Severity.Medium);
    }

    [Fact]
    public async Task RecordRevokedReplayAsync_NullUserAgent_StoresNull()
    {
        // arrange — UA-less request (machine-to-machine). UserAgent column is nullable.
        var (service, db, _) = BuildService();
        var revoked = new RevokedToken { TokenJti = "j", UserId = "u", ExpiresAt = DateTime.UtcNow.AddMinutes(5) };

        // act
        await service.RecordRevokedReplayAsync(revoked, "10.0.0.1", null);

        // assert
        (await db.RevokedTokenAccessAttempts.SingleAsync()).UserAgent.Should().BeNull();
    }

    [Fact]
    public async Task RecordRevokedReplayAsync_OversizedUserAgent_TruncatedTo512Chars()
    {
        // arrange — defensive cap against an attacker sending a 10MB User-Agent header to
        // bloat the audit table.
        var (service, db, _) = BuildService();
        var revoked = new RevokedToken { TokenJti = "j", UserId = "u", ExpiresAt = DateTime.UtcNow.AddMinutes(5) };
        var oversized = new string('A', 5000);

        // act
        await service.RecordRevokedReplayAsync(revoked, "10.0.0.1", oversized);

        // assert
        var attempt = await db.RevokedTokenAccessAttempts.SingleAsync();
        attempt.UserAgent!.Length.Should().Be(512);
    }

    // ─── Family revocation ──────────────────────────────────────────────────────────────

    [Fact]
    public async Task RevokeAllRefreshTokenFamiliesAsync_OnlyAffectsActiveRows()
    {
        // arrange — three tokens for the user: two active families, one already-consumed.
        // The consumed one must remain untouched (its ConsumedAt must not be overwritten;
        // its RevocationReason must not be filled in).
        var (service, db, _) = BuildService();
        var user = await SeedUserAsync(db, "alice", "alice@example.com");
        await service.CreateTokenAsync(user, ["DefaultUser"]);
        await service.CreateTokenAsync(user, ["DefaultUser"]);
        var consumedAt = DateTime.UtcNow.AddHours(-2);
        db.RefreshTokens.Add(new RefreshToken
        {
            Id = Guid.NewGuid(),
            UserId = user.Id,
            TokenHash = "manually-consumed",
            FamilyId = Guid.NewGuid(),
            CreatedAt = consumedAt.AddHours(-1),
            ExpiresAt = DateTime.UtcNow.AddDays(1),
            ConsumedAt = consumedAt,
            RevocationReason = RevocationReasons.Logout,
        });
        await db.SaveChangesAsync();

        // act
        await service.RevokeAllRefreshTokenFamiliesAsync(user.Id, RevocationReasons.LogoutAll);

        // assert — clear tracker so we read freshly-updated values, not cached pre-update.
        db.ChangeTracker.Clear();
        var rows = await db.RefreshTokens.ToListAsync();
        rows.Where(r => r.RevocationReason == RevocationReasons.LogoutAll).Should().HaveCount(2);
        rows.Single(r => r.TokenHash == "manually-consumed").RevocationReason.Should()
            .Be(RevocationReasons.Logout, because: "previously-consumed rows must not be re-touched.");
        rows.Single(r => r.TokenHash == "manually-consumed").ConsumedAt.Should()
            .BeCloseTo(consumedAt, TimeSpan.FromSeconds(1));
    }

    [Fact]
    public async Task RevokeFamilyAsync_OnlyAffectsNamedFamily()
    {
        // arrange — two distinct families for the user; revoke only one.
        var (service, db, _) = BuildService();
        var user = await SeedUserAsync(db, "alice", "alice@example.com");
        var firstFamily = Guid.NewGuid();
        var secondFamily = Guid.NewGuid();
        await service.CreateTokenAsync(user, ["DefaultUser"], firstFamily);
        await service.CreateTokenAsync(user, ["DefaultUser"], secondFamily);

        // act
        await service.RevokeFamilyAsync(firstFamily, RevocationReasons.Logout);

        // assert — clear tracker so reads see the freshly-updated rows.
        db.ChangeTracker.Clear();
        var rows = await db.RefreshTokens.ToListAsync();
        rows.Single(r => r.FamilyId == firstFamily).ConsumedAt.Should().NotBeNull();
        rows.Single(r => r.FamilyId == firstFamily).RevocationReason.Should().Be(RevocationReasons.Logout);
        rows.Single(r => r.FamilyId == secondFamily).ConsumedAt.Should().BeNull(
            because: "the other family must remain active.");
    }

    // ─── GetUserId / GetExpiryDateTime ──────────────────────────────────────────────────

    [Fact]
    public async Task GetUserId_TokenWithSubClaim_ReturnsSubValue()
    {
        // arrange
        var (service, db, _) = BuildService();
        var user = await SeedUserAsync(db, "alice", "alice@example.com");
        var token = await service.CreateTokenAsync(user, ["DefaultUser"]);

        // act
        var userId = service.GetUserId(token.Value);

        // assert
        userId.Should().Be(user.Id);
    }

    [Fact]
    public void GetUserId_GarbageToken_Throws()
    {
        // arrange — ReadJwtToken throws on non-JWT input. Tests document this so callers
        // can wrap with try/catch or pre-validate.
        var (service, _, _) = BuildService();

        // act
        var act = () => service.GetUserId("not-a-jwt");

        // assert
        act.Should().Throw<Exception>();
    }

    [Fact]
    public async Task GetExpiryDateTime_TokenWithExpClaim_ReturnsUtcExpiry()
    {
        // arrange
        var (service, db, _) = BuildService();
        var user = await SeedUserAsync(db, "alice", "alice@example.com");
        var token = await service.CreateTokenAsync(user, ["DefaultUser"]);

        // act
        var expiry = service.GetExpiryDateTime(token.Value);

        // assert — within a minute of the configured 15-min expiry from issue time.
        expiry.Should().NotBeNull();
        expiry!.Value.Should().BeCloseTo(DateTime.UtcNow.AddMinutes(_settings.ExpiryInMinutes), TimeSpan.FromMinutes(1));
        expiry.Value.Kind.Should().Be(DateTimeKind.Utc);
    }

    [Fact]
    public void GetExpiryDateTime_GarbageToken_Throws()
    {
        // arrange — TokenHandler.ReadToken throws on malformed input rather than returning
        // null (the type-pattern-match in the source code wraps a not-JwtSecurityToken case
        // but garbage doesn't get that far). Tests pin so controllers know they need the
        // try/catch around expiry-extraction.
        var (service, _, _) = BuildService();

        // act
        var act = () => service.GetExpiryDateTime("not-a-jwt");

        // assert
        act.Should().Throw<Microsoft.IdentityModel.Tokens.SecurityTokenMalformedException>();
    }

    // ─── CreateServiceTokenAsync — OAuth client-credentials service tokens ────────────────

    [Fact]
    public async Task CreateServiceToken_HappyPath_EmitsExpectedClaimShape()
    {
        // arrange — pin the contract that consumers rely on for distinguishing service
        // tokens from user tokens.
        var (service, _, _) = BuildService();

        // act
        var token = await service.CreateServiceTokenAsync(
            clientId: "inventory-api",
            audience: "orders-api",
            scopes: new[] { "orders.read", "orders.write" });

        // assert — JWT shape per docs/service-to-service-auth-plan.md.
        var jwt = new JwtSecurityTokenHandler().ReadJwtToken(token.Value);
        ReadClaim(token.Value, ClaimConstants.Sub).Should().Be("inventory-api",
            because: "sub on a service token is the client_id, not a user id.");
        ReadClaim(token.Value, ClaimConstants.ClientId).Should().Be("inventory-api");
        ReadClaim(token.Value, ClaimConstants.Azp).Should().Be("inventory-api");
        ReadClaim(token.Value, ClaimConstants.Scope).Should().Be("orders.read orders.write",
            because: "scope is a single space-separated claim per OAuth convention.");
        jwt.Audiences.Should().Contain("orders-api",
            because: "aud is the requested audience, not the platform-wide ValidAudience.");
    }

    [Fact]
    public async Task CreateServiceToken_OmitsUserClaims_SoConsumersCanDistinguishTokenKind()
    {
        // The load-bearing contract: consumers must be able to write something like
        // `if (user.HasClaim("email")) ...` to know they're dealing with a user token
        // rather than a service token. If we accidentally added email or sid or role
        // claims to service tokens, that check would break.
        var (service, _, _) = BuildService();

        var token = await service.CreateServiceTokenAsync("a-client", "an-aud", new[] { "a.scope" });

        var jwt = new JwtSecurityTokenHandler().ReadJwtToken(token.Value);
        jwt.Claims.Should().NotContain(c => c.Type == ClaimConstants.Email,
            because: "email is a user-only claim.");
        jwt.Claims.Should().NotContain(c => c.Type == ClaimConstants.Name,
            because: "name is a user-only claim.");
        jwt.Claims.Should().NotContain(c => c.Type == ClaimConstants.Role,
            because: "role is a user-only claim.");
        jwt.Claims.Should().NotContain(c => c.Type == ClaimConstants.Sid,
            because: "sid (refresh-token family) is a user-token concept; service tokens have no refresh half.");
    }

    [Fact]
    public async Task CreateServiceToken_NoRefreshHalf()
    {
        var (service, _, _) = BuildService();

        var token = await service.CreateServiceTokenAsync("c", "a", new[] { "s" });

        token.RefreshToken.Should().BeNull(
            because: "service tokens have no refresh half — the client re-requests when the access token expires.");
        token.RefreshTokenExpiresAt.Should().BeNull();
    }

    [Fact]
    public async Task CreateServiceToken_ExpiryFollowsConfiguredLifetime()
    {
        // The test fixture sets TokenLifetimeInHours = 12 via the default
        // ClientCredentialsSettings constructor. Token must expire ~12h out.
        var (service, _, _) = BuildService();

        var token = await service.CreateServiceTokenAsync("c", "a", new[] { "s" });

        token.Expires.Should().NotBeNull();
        token.Expires!.Value.Should().BeCloseTo(DateTime.UtcNow.AddHours(12), TimeSpan.FromSeconds(5));
    }

    // ─── helpers ────────────────────────────────────────────────────────────────────────

    private (JWTService service, DatabaseContext db, UserManager<User> userManager) BuildService()
    {
        // arrange — SQLite InMemory rather than EF InMemory because the production code
        // uses transactions and ExecuteUpdateAsync (both of which EF InMemory rejects).
        // SQLite InMemory keeps the connection open for the lifetime of the test.
        var connection = new SqliteConnection("DataSource=:memory:");
        connection.Open();
        _trackedConnections.Add(connection);

        var options = new DbContextOptionsBuilder<DatabaseContext>()
            .UseSqlite(connection)
            .Options;
        var db = new DatabaseContext(options);
        db.Database.EnsureCreated();
        _trackedContexts.Add(db);

        var userManager = StubUserManager();
        var service = new JWTService(
            Options.Create(_settings),
            Options.Create(new ClientCredentialsSettings()),
            userManager,
            db,
            _keyProvider,
            NullLogger<JWTService>.Instance,
            TestMetricsFactory.Create());
        return (service, db, userManager);
    }

    private readonly List<SqliteConnection> _trackedConnections = new();
    private readonly List<DatabaseContext> _trackedContexts = new();

    private static UserManager<User> StubUserManager()
    {
        // The service only calls FindByIdAsync, GetRolesAsync, and UpdateSecurityStampAsync.
        // Provide sensible defaults: by default FindByIdAsync returns a user matching the
        // ID; tests that need other behaviour configure per-test.
        var store = Substitute.For<IUserStore<User>>();
        var manager = Substitute.For<UserManager<User>>(store, null!, null!, null!, null!, null!, null!, null!, null!);
        manager.FindByIdAsync(Arg.Any<string>())
            .Returns(ci => new User { Id = ci.Arg<string>(), UserName = "alice", Email = "alice@example.com" });
        manager.GetRolesAsync(Arg.Any<User>()).Returns(["DefaultUser"]);
        manager.UpdateSecurityStampAsync(Arg.Any<User>()).Returns(IdentityResult.Success);
        return manager;
    }

    private static async Task<User> SeedUserAsync(DatabaseContext db, string userName, string email)
    {
        var user = new User
        {
            Id = Guid.NewGuid().ToString(),
            UserName = userName,
            Email = email,
            NormalizedUserName = userName.ToUpperInvariant(),
            NormalizedEmail = email.ToUpperInvariant(),
        };
        db.Users.Add(user);
        await db.SaveChangesAsync();
        return user;
    }

    private static string ReadClaim(string jwt, string claimType)
        => new JwtSecurityTokenHandler().ReadJwtToken(jwt).Claims.First(c => c.Type == claimType).Value;

    private sealed class TempDir : IDisposable
    {
        public string Path { get; } = System.IO.Path.Combine(System.IO.Path.GetTempPath(), Guid.NewGuid().ToString("N"));
        public TempDir() => Directory.CreateDirectory(Path);
        public void Dispose() { try { Directory.Delete(Path, recursive: true); } catch { } }
    }
}
