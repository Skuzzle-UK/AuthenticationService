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
/// Drives the signing-key + JWKS-publishing behaviour. Covers happy paths, error paths
/// (empty dir in prod, unknown ActiveKeyId), caching, dispose semantics.
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
        GC.SuppressFinalize(this);
    }

    // ─── happy path ─────────────────────────────────────────────────────────────────────

    [Fact]
    public void Construction_WithSingleKey_LoadsAndPublishesJwksDocument()
    {
        // arrange
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
        // arrange — "auto" picks first by Directory.GetFiles ordering; pinned because dev/single-key flows depend on this.
        WritePem("k1.pem");
        WritePem("k2.pem");

        // act
        using var provider = MakeProvider("auto");

        // assert
        provider.PublicJsonWebKeys.Should().HaveCount(2);
        provider.JwksDocument.Keys.Should().HaveCount(2);
        provider.JwksDocument.Keys.Select(k => k.Kid).Should().Contain(provider.KeyId);
    }

    [Fact]
    public void Construction_ExplicitActiveKeyId_SelectsThatKey()
    {
        // arrange — simulates rotation: operator advances ActiveKeyId to the new key's thumbprint.
        WritePem("k1.pem");
        WritePem("k2.pem");
        using var probe = MakeProvider("auto");
        var allKids = probe.PublicJsonWebKeys.Select(j => j.Kid).ToList();
        var secondKid = allKids.First(k => k != probe.KeyId);

        // act
        using var provider = MakeProvider(secondKid);

        // assert
        provider.KeyId.Should().Be(secondKid);
        provider.PublicJsonWebKeys.Select(j => j.Kid).Should().Contain(allKids);
    }

    [Fact]
    public void Construction_ExplicitActiveKeyIdEmptyString_FallsBackToAuto()
    {
        // arrange — operators may try blank instead of the "auto" sentinel.
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
        // arrange — better to throw at startup than silently fall back to a different key.
        WritePem("k1.pem");

        // act + assert
        var act = () => MakeProvider("wrong-thumbprint");

        act.Should().Throw<InvalidOperationException>()
            .WithMessage("*ActiveKeyId*'wrong-thumbprint'*Available keys*");
    }

    [Fact]
    public void Construction_EmptyDirectoryInProduction_Throws()
    {
        // act + assert — production must not silently generate a brand-new signing key; operator provisions via deploy.
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

        act.Should().Throw<InvalidOperationException>()
            .WithMessage("*No JWT signing keys*Auto-generation is disabled outside Development*");
    }

    [Fact]
    public void Construction_EmptyDirectoryInDevelopment_AutoGeneratesKey()
    {
        // act — dev convenience: first `dotnet run` against a fresh checkout shouldn't need manual provisioning.
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
        Directory.GetFiles(_tempDir, "*.pem").Should().HaveCount(1);
        provider.PublicJsonWebKeys.Should().HaveCount(1);
        provider.JwksDocument.Keys.Should().HaveCount(1);
    }

    [Fact]
    public void Construction_NonExistentDirectory_CreatesItRatherThanThrow()
    {
        // arrange — first-startup ergonomic: missing directory shouldn't crash before generation can run.
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
        // arrange
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
        // arrange — doc must mirror PublicJsonWebKeys exactly; drift would publish a different key set than what validates.
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
        // arrange — service-collection lifetime can dispose singletons during shutdown.
        WritePem("k1.pem");
        var provider = MakeProvider("auto");

        // act + assert
        var act = () => { provider.Dispose(); provider.Dispose(); };

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
