using System.Security.Cryptography;
using AuthenticationService.Constants;
using AuthenticationService.Controllers;
using AuthenticationService.Services;
using AuthenticationService.Settings;
using AwesomeAssertions;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using NSubstitute;

namespace AuthenticationService.Tests.Controllers;

/// <summary>
/// Covers JWKS + OIDC discovery — the most-hit anonymous endpoint (every consumer polls JWKS).
/// </summary>
public class WellKnownControllerTests : IDisposable
{
    private readonly string _keyDir = Path.Combine(Path.GetTempPath(), "wellknown-tests-" + Guid.NewGuid().ToString("N"));
    private readonly EcdsaKeyProvider _keyProvider;

    public WellKnownControllerTests()
    {
        Directory.CreateDirectory(_keyDir);
        using var ec = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        File.WriteAllText(Path.Combine(_keyDir, "key.pem"), ec.ExportECPrivateKeyPem());

        var env = Substitute.For<IHostEnvironment>();
        env.EnvironmentName.Returns(Environments.Development);
        env.ContentRootPath.Returns(Path.GetTempPath());
        _keyProvider = new EcdsaKeyProvider(
            Options.Create(new JWTSettings
            {
                PrivateKeyDirectory = _keyDir,
                ActiveKeyId = "auto",
                ValidIssuer = "https://auth.test", ValidAudience = "test-aud",
                ExpiryInMinutes = 15, RefreshTokenExpiryInDays = 14,
            }),
            env, NullLogger<EcdsaKeyProvider>.Instance);
    }

    public void Dispose()
    {
        _keyProvider.Dispose();
        try { Directory.Delete(_keyDir, recursive: true); } catch { /* best-effort */ }
    }

    [Fact]
    public void Jwks_ReturnsCachedJwksDocumentFromKeyProvider()
    {
        // Pinned by reference equality — a regression that rebuilds per call would slip through value equality.
        var controller = MakeController();

        var result = controller.Jwks();

        var ok = result.Should().BeOfType<OkObjectResult>().Subject;
        ok.Value.Should().BeSameAs(_keyProvider.JwksDocument);
    }

    [Fact]
    public void OpenIdConfiguration_BuildsDiscoveryDocFromConfiguredPublicUrlAndJwtSettings()
    {
        // Host part comes from PublicUrlSettings rather than the request — defends against host-header attacks.
        var controller = MakeController();

        var result = controller.OpenIdConfiguration();

        var ok = result.Should().BeOfType<OkObjectResult>().Subject;
        var body = ok.Value!;
        var type = body.GetType();
        type.GetProperty("issuer")!.GetValue(body).Should().Be("https://auth.test");
        type.GetProperty("jwks_uri")!.GetValue(body).Should().Be(
            $"https://example.com/{WellKnownPaths.Prefix}/{WellKnownPaths.Jwks}");
        var algs = (string[])type.GetProperty("id_token_signing_alg_values_supported")!.GetValue(body)!;
        algs.Should().BeEquivalentTo(["ES256"]);
    }

    private WellKnownController MakeController() => new(
        _keyProvider,
        Options.Create(new JWTSettings
        {
            PrivateKeyDirectory = "ignored",
            ActiveKeyId = "auto",
            ValidIssuer = "https://auth.test",
            ValidAudience = "test-aud",
            ExpiryInMinutes = 15, RefreshTokenExpiryInDays = 14,
        }),
        Options.Create(new PublicUrlSettings { BaseUrl = "https://example.com" }));
}
