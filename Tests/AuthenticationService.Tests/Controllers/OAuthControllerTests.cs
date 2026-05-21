using System.Net;
using System.Text;
using AuthenticationService.Controllers;
using AuthenticationService.Entities;
using AuthenticationService.Services;
using AuthenticationService.Settings;
using AuthenticationService.Shared.Constants;
using AuthenticationService.Shared.Dtos.Response;
using AuthenticationService.Shared.Models;
using AuthenticationService.Tests.Helpers;
using AwesomeAssertions;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Microsoft.Net.Http.Headers;
using NSubstitute;

namespace AuthenticationService.Tests.Controllers;

/// <summary>
/// Pins the RFC 6749 error-mapping contract for <see cref="OAuthController"/>: every error code,
/// the credential-extraction precedence (Basic header preferred, body fills in, disagree rejected),
/// and the happy path.
/// </summary>
public class OAuthControllerTests
{
    private const string ClientId = "test-client";
    private const string ClientSecret = "test-secret";
    private const string Audience = "inventory-api";

    // ─── HTTPS gate ────────────────────────────────────────────────────────────────

    [Fact]
    public async Task TokenAsync_HttpsRequiredButHttp_ReturnsInvalidRequest()
    {
        var (controller, _) = BuildController(requireHttps: true, isHttps: false);

        var result = await controller.TokenAsync(MakeRequest(), CancellationToken.None);

        AssertError(result, HttpStatusCode.BadRequest, "invalid_request");
    }

    [Fact]
    public async Task TokenAsync_HttpsDisabledInConfig_AllowsHttpThrough()
    {
        // Integration-test mode flips RequireHttps off.
        var (controller, deps) = BuildController(requireHttps: false, isHttps: false);
        StubHappyPath(deps);

        var result = await controller.TokenAsync(MakeRequest(), CancellationToken.None);

        result.Should().BeOfType<OkObjectResult>();
    }

    // ─── Grant type ────────────────────────────────────────────────────────────────

    [Fact]
    public async Task TokenAsync_UnknownGrantType_ReturnsUnsupportedGrantType()
    {
        var (controller, _) = BuildController();

        var result = await controller.TokenAsync(
            MakeRequest(grantType: "password"), CancellationToken.None);

        AssertError(result, HttpStatusCode.BadRequest, "unsupported_grant_type");
    }

    // ─── Credential extraction ──────────────────────────────────────────────────────

    [Fact]
    public async Task TokenAsync_NoCredentialsAnywhere_ReturnsInvalidRequest()
    {
        var (controller, _) = BuildController();

        var result = await controller.TokenAsync(
            MakeRequest(clientId: null, clientSecret: null), CancellationToken.None);

        AssertError(result, HttpStatusCode.BadRequest, "invalid_request");
    }

    [Fact]
    public async Task TokenAsync_MalformedBasicHeader_ReturnsInvalidRequest()
    {
        var (controller, _) = BuildController();
        controller.ControllerContext.HttpContext.Request.Headers[HeaderNames.Authorization] = "Basic !!!not-base64!!!";

        var result = await controller.TokenAsync(
            MakeRequest(clientId: null, clientSecret: null), CancellationToken.None);

        AssertError(result, HttpStatusCode.BadRequest, "invalid_request");
    }

    [Fact]
    public async Task TokenAsync_NonBasicAuthScheme_ReturnsInvalidRequest()
    {
        var (controller, _) = BuildController();
        controller.ControllerContext.HttpContext.Request.Headers[HeaderNames.Authorization] = "Bearer some-token";

        var result = await controller.TokenAsync(
            MakeRequest(clientId: null, clientSecret: null), CancellationToken.None);

        AssertError(result, HttpStatusCode.BadRequest, "invalid_request");
    }

    [Fact]
    public async Task TokenAsync_HeaderAndBodyDisagree_ReturnsInvalidRequest()
    {
        var (controller, _) = BuildController();
        SetBasicAuthHeader(controller, ClientId, ClientSecret);

        var result = await controller.TokenAsync(
            MakeRequest(clientId: "different-client", clientSecret: ClientSecret),
            CancellationToken.None);

        AssertError(result, HttpStatusCode.BadRequest, "invalid_request");
    }

    [Fact]
    public async Task TokenAsync_BasicAuthHeaderOnly_HappyPath_Returns200()
    {
        var (controller, deps) = BuildController();
        SetBasicAuthHeader(controller, ClientId, ClientSecret);
        StubHappyPath(deps);

        var result = await controller.TokenAsync(
            MakeRequest(clientId: null, clientSecret: null), CancellationToken.None);

        result.Should().BeOfType<OkObjectResult>();
    }

    // ─── Client + secret verification ──────────────────────────────────────────────

    [Fact]
    public async Task TokenAsync_UnknownClient_Returns401InvalidClient()
    {
        var (controller, deps) = BuildController();
        deps.ClientService.FindActiveAsync(ClientId, Arg.Any<CancellationToken>()).Returns((Client?)null);

        var result = await controller.TokenAsync(MakeRequest(), CancellationToken.None);

        AssertError(result, HttpStatusCode.Unauthorized, "invalid_client");
        controller.Response.Headers[HeaderNames.WWWAuthenticate].ToString()
            .Should().StartWith("Basic",
                because: "invalid_client must carry WWW-Authenticate: Basic per RFC 6749 §5.2.");
    }

    [Fact]
    public async Task TokenAsync_BadSecret_Returns401InvalidClient()
    {
        var (controller, deps) = BuildController();
        var client = new Client { Id = ClientId, Name = "T", ClientSecretHash = "any" };
        deps.ClientService.FindActiveAsync(ClientId, Arg.Any<CancellationToken>()).Returns(client);
        deps.ClientService.VerifySecret(client, ClientSecret).Returns(false);

        var result = await controller.TokenAsync(MakeRequest(), CancellationToken.None);

        AssertError(result, HttpStatusCode.Unauthorized, "invalid_client");
    }

    // ─── audience + scope validation ───────────────────────────────────────────────

    [Fact]
    public async Task TokenAsync_MissingAudience_ReturnsInvalidRequest()
    {
        var (controller, deps) = BuildController();
        StubHappyPath(deps);

        var result = await controller.TokenAsync(
            MakeRequest(audience: null), CancellationToken.None);

        AssertError(result, HttpStatusCode.BadRequest, "invalid_request");
    }

    [Fact]
    public async Task TokenAsync_MissingScope_ReturnsInvalidRequest()
    {
        var (controller, deps) = BuildController();
        StubHappyPath(deps);

        var result = await controller.TokenAsync(
            MakeRequest(scope: null), CancellationToken.None);

        AssertError(result, HttpStatusCode.BadRequest, "invalid_request");
    }

    [Fact]
    public async Task TokenAsync_UnauthorisedScope_ReturnsInvalidScope()
    {
        var (controller, deps) = BuildController();
        var client = new Client { Id = ClientId, Name = "T", ClientSecretHash = "any" };
        deps.ClientService.FindActiveAsync(ClientId, Arg.Any<CancellationToken>()).Returns(client);
        deps.ClientService.VerifySecret(client, ClientSecret).Returns(true);
        deps.ClientService.HasScopeAsync(ClientId, Audience, Arg.Any<string>(), Arg.Any<CancellationToken>())
            .Returns(false);

        var result = await controller.TokenAsync(
            MakeRequest(scope: "inventory.read inventory.write"), CancellationToken.None);

        AssertError(result, HttpStatusCode.BadRequest, "invalid_scope");
    }

    [Fact]
    public async Task TokenAsync_OneScopeAuthorisedOneNot_ReturnsInvalidScope()
    {
        // No partial grants — all or nothing.
        var (controller, deps) = BuildController();
        var client = new Client { Id = ClientId, Name = "T", ClientSecretHash = "any" };
        deps.ClientService.FindActiveAsync(ClientId, Arg.Any<CancellationToken>()).Returns(client);
        deps.ClientService.VerifySecret(client, ClientSecret).Returns(true);
        deps.ClientService.HasScopeAsync(ClientId, Audience, "inventory.read", Arg.Any<CancellationToken>())
            .Returns(true);
        deps.ClientService.HasScopeAsync(ClientId, Audience, "inventory.write", Arg.Any<CancellationToken>())
            .Returns(false);

        var result = await controller.TokenAsync(
            MakeRequest(scope: "inventory.read inventory.write"), CancellationToken.None);

        AssertError(result, HttpStatusCode.BadRequest, "invalid_scope");
        await deps.TokenService.DidNotReceiveWithAnyArgs().CreateServiceTokenAsync(default!, default!, default!);
    }

    // ─── Happy path ────────────────────────────────────────────────────────────────

    [Fact]
    public async Task TokenAsync_HappyPath_ReturnsTokenAndStampsLastUsed()
    {
        var (controller, deps) = BuildController();
        StubHappyPath(deps);

        var result = await controller.TokenAsync(MakeRequest(), CancellationToken.None);

        var ok = result.Should().BeOfType<OkObjectResult>().Subject;
        var body = ok.Value.Should().BeOfType<OAuthTokenResponse>().Subject;
        body.AccessToken.Should().Be("issued-jwt");
        body.TokenType.Should().Be("Bearer");
        body.ExpiresIn.Should().BeGreaterThan(0);
        body.Scope.Should().Be("inventory.read");

        await deps.ClientService.Received(1).TouchLastUsedAsync(ClientId, Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task TokenAsync_HappyPath_DeduplicatesScopes()
    {
        // Duplicated scopes in request collapse before authorisation — token + response carry each distinct scope once.
        var (controller, deps) = BuildController();
        StubHappyPath(deps);

        var result = await controller.TokenAsync(
            MakeRequest(scope: "inventory.read inventory.read"), CancellationToken.None);

        var ok = result.Should().BeOfType<OkObjectResult>().Subject;
        var body = ok.Value.Should().BeOfType<OAuthTokenResponse>().Subject;
        body.Scope.Should().Be("inventory.read",
            because: "duplicate scope entries in the request collapse to a single granted scope.");
    }

    // ─── Helpers ───────────────────────────────────────────────────────────────────

    private static (OAuthController controller, Deps deps) BuildController(
        bool requireHttps = false,
        bool isHttps = true)
    {
        var deps = new Deps
        {
            ClientService = Substitute.For<IClientService>(),
            TokenService = Substitute.For<ITokenService>(),
        };

        var settings = Options.Create(new ClientCredentialsSettings
        {
            RequireHttps = requireHttps,
            TokenLifetimeInHours = 12,
        });

        var controller = new OAuthController(
            deps.ClientService,
            deps.TokenService,
            settings,
            NullLogger<OAuthController>.Instance,
            TestMetricsFactory.Create());

        var http = new DefaultHttpContext
        {
            Request = { Scheme = isHttps ? "https" : "http" },
            Connection = { RemoteIpAddress = System.Net.IPAddress.Parse("10.0.0.5") },
        };
        controller.ControllerContext = new ControllerContext { HttpContext = http };
        return (controller, deps);
    }

    private static OAuthTokenRequest MakeRequest(
        string? grantType = "client_credentials",
        string? clientId = ClientId,
        string? clientSecret = ClientSecret,
        string? audience = Audience,
        string? scope = "inventory.read") => new()
    {
        GrantType = grantType,
        ClientId = clientId,
        ClientSecret = clientSecret,
        Audience = audience,
        Scope = scope,
    };

    /// <summary>
    /// Configures the dep stubs so the controller accepts credentials, passes scope checks, and emits a token.
    /// Tests that want to fail at a specific step then override the relevant call.
    /// </summary>
    private static void StubHappyPath(Deps deps)
    {
        var client = new Client { Id = ClientId, Name = "T", ClientSecretHash = "any" };
        deps.ClientService.FindActiveAsync(ClientId, Arg.Any<CancellationToken>()).Returns(client);
        deps.ClientService.VerifySecret(client, ClientSecret).Returns(true);
        deps.ClientService.HasScopeAsync(ClientId, Audience, Arg.Any<string>(), Arg.Any<CancellationToken>())
            .Returns(true);
        deps.TokenService.CreateServiceTokenAsync(ClientId, Audience, Arg.Any<IEnumerable<string>>())
            .Returns(new Token
            {
                Type = "Bearer",
                Value = "issued-jwt",
                Expires = DateTime.UtcNow.AddHours(12),
            });
    }

    private static void SetBasicAuthHeader(OAuthController controller, string id, string secret)
    {
        var encoded = Convert.ToBase64String(Encoding.UTF8.GetBytes($"{id}:{secret}"));
        controller.ControllerContext.HttpContext.Request.Headers[HeaderNames.Authorization] = $"Basic {encoded}";
    }

    private static void AssertError(IActionResult result, HttpStatusCode expectedStatus, string expectedError)
    {
        var status = result switch
        {
            ObjectResult obj => obj.StatusCode,
            _ => null,
        };
        status.Should().Be((int)expectedStatus);

        var body = ((ObjectResult)result).Value.Should().BeOfType<OAuthErrorResponse>().Subject;
        body.Error.Should().Be(expectedError);
    }

    private sealed class Deps
    {
        public IClientService ClientService { get; set; } = default!;
        public ITokenService TokenService { get; set; } = default!;
    }
}
