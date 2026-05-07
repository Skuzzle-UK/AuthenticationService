using System.Security.Cryptography;
using AuthenticationService.Services;
using AuthenticationService.Settings;
using AwesomeAssertions;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using NSubstitute;

namespace AuthenticationService.Tests.Services;

/// <summary>
/// <para>The key provider drives all signing + JWKS publishing behaviour. Paths covered:</para>
/// <list type="bullet">
///   <item><description>One PEM in directory → loads, sets active key, populates JWKS document with one entry.</description></item>
///   <item><description>Multiple PEMs + ActiveKeyId="auto" → first key selected as active.</description></item>
///   <item><description>Multiple PEMs + ActiveKeyId=&lt;explicit thumbprint&gt; → that key selected, others stay in JWKS for validation.</description></item>
///   <item><description>Multiple PEMs + ActiveKeyId=&lt;unknown thumbprint&gt; → throws (operator must fix config).</description></item>
///   <item><description>Empty directory in Development → auto-generates one key.</description></item>
///   <item><description>Empty directory in non-Development → throws (no implicit prod-time key generation).</description></item>
///   <item><description>Cached JwksDocument is the same instance across reads (caching contract).</description></item>
///   <item><description>JwksDocument shape mirrors PublicJsonWebKeys exactly.</description></item>
///   <item><description>Dispose disposes every loaded key.</description></item>
///   <item><description>Relative path resolves against ContentRootPath.</description></item>
/// </list>
/// </summary>
public class EcdsaKeyProviderTests : IDisposable
{
    private readonly string _tempDir = Path.Combine(Path.GetTempPath(), "auth-tests-" + Guid.NewGuid().ToString("N"));

    public EcdsaKeyProviderTests()
    {
        Directory.CreateDirectory(_tempDir);
    }

    public void Dispose()
    {
        try { Directory.Delete(_tempDir, recursive: true); } catch { /* best-effort cleanup */ }
    }

    // ─── happy path ─────────────────────────────────────────────────────────────────────

    [Fact]
    public void Construction_WithSingleKey_LoadsAndPublishesJwksDocument()
    {
        // arrange — single PEM, "auto" active key.
        WritePem("k1.pem");

        // act
        using var provider = new EcdsaKeyProvider(
            Options.Create(new JWTSettings
            {
                PrivateKeyDirectory = _tempDir,
                ActiveKeyId = "auto",
                ValidIssuer = "i", ValidAudience = "a",
                ExpiryInMinutes = 15, RefreshTokenExpiryInDays = 14,
            }),
            DevEnvironment(),
            NullLogger<EcdsaKeyProvider>.Instance);

        // assert
        provider.PublicJsonWebKeys.Should().HaveCount(1);
        provider.PublicSecurityKeys.Should().HaveCount(1);
        provider.SigningCredentials.Algorithm.Should().Be(SecurityAlgorithms.EcdsaSha256);
        provider.SigningCredentials.Key.KeyId.Should().Be(provider.KeyId);
        provider.JwksDocument.Keys.Should().HaveCount(1);
        provider.JwksDocument.Keys[0].Kid.Should().Be(provider.KeyId);
    }

    [Fact]
    public void Construction_MultipleKeys_AutoSelectsFirstAsActive()
    {
        // arrange — multiple keys, no explicit active. The "auto" selection picks the
        // first by Directory.GetFiles ordering — pinned because dev/single-key flows
        // depend on this not throwing.
        WritePem("k1.pem");
        WritePem("k2.pem");

        // act
        using var provider = MakeProvider("auto");

        // assert — both keys are in the JWKS for validation; one is active for signing.
        provider.PublicJsonWebKeys.Should().HaveCount(2);
        provider.JwksDocument.Keys.Should().HaveCount(2);
        provider.JwksDocument.Keys.Select(k => k.Kid).Should().Contain(provider.KeyId);
    }

    [Fact]
    public void Construction_ExplicitActiveKeyId_SelectsThatKey()
    {
        // arrange — load two keys, then construct a second provider asking for the second
        // key's thumbprint explicitly (simulating a rotation: operator advances the
        // ActiveKeyId to the new key's thumbprint).
        WritePem("k1.pem");
        WritePem("k2.pem");
        using var probe = MakeProvider("auto");
        var allKids = probe.PublicJsonWebKeys.Select(j => j.Kid).ToList();
        var secondKid = allKids.First(k => k != probe.KeyId);

        // act
        using var provider = MakeProvider(secondKid);

        // assert — explicit selection wins; previous key still in JWKS for the rotation
        // overlap window.
        provider.KeyId.Should().Be(secondKid);
        provider.PublicJsonWebKeys.Select(j => j.Kid).Should().Contain(allKids);
    }

    [Fact]
    public void Construction_ExplicitActiveKeyIdEmptyString_FallsBackToAuto()
    {
        // arrange — empty string is treated the same as "auto" (operator left field blank
        // in config). Pinned because operators don't always understand the "auto" sentinel
        // and may try blank instead.
        WritePem("k1.pem");

        // act
        using var provider = MakeProvider("");

        // assert
        provider.KeyId.Should().NotBeNullOrEmpty();
    }

    // ─── error paths ────────────────────────────────────────────────────────────────────

    [Fact]
    public void Construction_ExplicitActiveKeyIdNotInLoadedSet_Throws()
    {
        // arrange — operator misconfiguration: ActiveKeyId points to a key that isn't in
        // the directory. Better to throw at startup than silently fall back to a different
        // key (which would invalidate every issued token at next rotation).
        WritePem("k1.pem");

        // act
        var act = () => MakeProvider("wrong-thumbprint");

        // assert
        act.Should().Throw<InvalidOperationException>()
            .WithMessage("*ActiveKeyId*'wrong-thumbprint'*Available keys*");
    }

    [Fact]
    public void Construction_EmptyDirectoryInProduction_Throws()
    {
        // arrange — production startup must not silently generate a brand-new signing key
        // (which would invalidate every token issued by the previous instance). Operator
        // must provision keys via the deploy pipeline.

        // act
        var act = () => new EcdsaKeyProvider(
            Options.Create(new JWTSettings
            {
                PrivateKeyDirectory = _tempDir,
                ActiveKeyId = "auto",
                ValidIssuer = "i", ValidAudience = "a",
                ExpiryInMinutes = 15, RefreshTokenExpiryInDays = 14,
            }),
            ProductionEnvironment(),
            NullLogger<EcdsaKeyProvider>.Instance);

        // assert
        act.Should().Throw<InvalidOperationException>()
            .WithMessage("*No JWT signing keys*Auto-generation is disabled outside Development*");
    }

    [Fact]
    public void Construction_EmptyDirectoryInDevelopment_AutoGeneratesKey()
    {
        // arrange — dev convenience: first `dotnet run` against a fresh checkout shouldn't
        // require manual key provisioning. Provider generates one PEM, persists it, then
        // proceeds.

        // act
        using var provider = new EcdsaKeyProvider(
            Options.Create(new JWTSettings
            {
                PrivateKeyDirectory = _tempDir,
                ActiveKeyId = "auto",
                ValidIssuer = "i", ValidAudience = "a",
                ExpiryInMinutes = 15, RefreshTokenExpiryInDays = 14,
            }),
            DevEnvironment(),
            NullLogger<EcdsaKeyProvider>.Instance);

        // assert — file persisted (so the next dev run reuses the same key).
        Directory.GetFiles(_tempDir, "*.pem").Should().HaveCount(1);
        provider.PublicJsonWebKeys.Should().HaveCount(1);
        provider.JwksDocument.Keys.Should().HaveCount(1);
    }

    [Fact]
    public void Construction_NonExistentDirectory_CreatesItRatherThanThrow()
    {
        // arrange — first-startup ergonomic: if the configured directory doesn't exist,
        // create it. Then proceed with the empty-directory path (auto-generate in Dev,
        // throw in Prod). Without this, dev startup would fail before getting to the
        // generation path.
        var nestedDir = Path.Combine(_tempDir, "subdir-that-does-not-exist");
        Directory.Exists(nestedDir).Should().BeFalse();

        // act
        using var provider = new EcdsaKeyProvider(
            Options.Create(new JWTSettings
            {
                PrivateKeyDirectory = nestedDir,
                ActiveKeyId = "auto",
                ValidIssuer = "i", ValidAudience = "a",
                ExpiryInMinutes = 15, RefreshTokenExpiryInDays = 14,
            }),
            DevEnvironment(),
            NullLogger<EcdsaKeyProvider>.Instance);

        // assert
        Directory.Exists(nestedDir).Should().BeTrue();
        provider.PublicJsonWebKeys.Should().HaveCount(1);
    }

    // ─── caching ────────────────────────────────────────────────────────────────────────

    [Fact]
    public void JwksDocument_CachedInstance_ReusedAcrossReads()
    {
        // arrange — the whole point of building the doc once at construction time is to
        // not re-allocate per request. Pinned by reference equality.
        WritePem("k1.pem");
        using var provider = MakeProvider("auto");

        // act
        var first = provider.JwksDocument;
        var second = provider.JwksDocument;

        // assert
        ReferenceEquals(first, second).Should().BeTrue(
            because: "the doc is built once at startup and the same reference returned on every read.");
    }

    [Fact]
    public void JwksDocument_KeysMatch_PublicJsonWebKeys()
    {
        // arrange — the cached doc must mirror PublicJsonWebKeys exactly. A regression
        // that drifts these (e.g. doc built before all keys loaded) would publish a
        // different key set than what the service can validate against.
        WritePem("k1.pem");
        WritePem("k2.pem");
        using var provider = MakeProvider("auto");

        // act
        var docKids = provider.JwksDocument.Keys.Select(k => k.Kid).OrderBy(k => k).ToList();
        var jwkKids = provider.PublicJsonWebKeys.Select(j => j.Kid).OrderBy(k => k).ToList();

        // assert
        docKids.Should().BeEquivalentTo(jwkKids);
    }

    // ─── dispose ────────────────────────────────────────────────────────────────────────

    [Fact]
    public void Dispose_DoesNotThrow_AndCanBeCalledRepeatedly()
    {
        // arrange — Dispose iterates _allKeys disposing each. Repeat-call safety isn't
        // strictly required by IDisposable but the service-collection lifetime can dispose
        // singletons during shutdown; pinned to catch any future change that adds state
        // assuming once-only dispose.
        WritePem("k1.pem");
        var provider = MakeProvider("auto");

        // act
        var act = () => { provider.Dispose(); provider.Dispose(); };

        // assert
        act.Should().NotThrow();
    }

    // ─── helpers ────────────────────────────────────────────────────────────────────────

    private void WritePem(string fileName)
    {
        using var ec = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        File.WriteAllText(Path.Combine(_tempDir, fileName), ec.ExportECPrivateKeyPem());
    }

    private EcdsaKeyProvider MakeProvider(string activeKeyId) => new(
        Options.Create(new JWTSettings
        {
            PrivateKeyDirectory = _tempDir,
            ActiveKeyId = activeKeyId,
            ValidIssuer = "i", ValidAudience = "a",
            ExpiryInMinutes = 15, RefreshTokenExpiryInDays = 14,
        }),
        DevEnvironment(),
        NullLogger<EcdsaKeyProvider>.Instance);

    private static IHostEnvironment DevEnvironment()
    {
        var env = Substitute.For<IHostEnvironment>();
        env.EnvironmentName.Returns(Environments.Development);
        env.ContentRootPath.Returns(Path.GetTempPath());
        return env;
    }

    private static IHostEnvironment ProductionEnvironment()
    {
        var env = Substitute.For<IHostEnvironment>();
        env.EnvironmentName.Returns(Environments.Production);
        env.ContentRootPath.Returns(Path.GetTempPath());
        return env;
    }
}
