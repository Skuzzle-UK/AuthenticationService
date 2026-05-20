using System.IdentityModel.Tokens.Jwt;
using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using AuthenticationService.Shared.Dtos;
using AuthenticationService.Shared.Dtos.Response;
using AuthenticationService.TokenClientLib;
using AwesomeAssertions;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace AuthenticationService.IntegrationTests.Scenarios;

/// <summary>
/// <para><b>Scenario 15 — Outgoing service-token plumbing end-to-end.</b></para>
///
/// <para>Closes the loop on Phase 1. Scenarios 13/14 covered the auth-service side
/// (admin creates client → <c>/oauth/token</c> issues JWT → scope authorisation enforced);
/// this one verifies the consumer side via the new <c>AuthenticationService.TokenClientLib</c>:
/// a typed <see cref="HttpClient"/> registered with <c>AddServiceToken("aud", "scope")</c>
/// stamps a real JWT (issued by the live auth service against a real <c>Clients</c> row)
/// on the outgoing call to a real (in-process) downstream stub.</para>
///
/// <para>What's exercised end-to-end:</para>
/// <list type="bullet">
///   <item><description>OIDC discovery against the running auth service — <c>TokenEndpointOverride</c> is deliberately not set, so the provider must resolve <c>token_endpoint</c> from <c>/.well-known/openid-configuration</c>.</description></item>
///   <item><description>Token fetch via <c>/oauth/token</c> with Basic-auth credentials. The exact JWT (jti included) lands on the downstream's <c>Authorization</c> header.</description></item>
///   <item><description>Cache hit on the second outgoing call — the same jti reaches the downstream both times, proving the auth service was not bothered for a fresh token.</description></item>
///   <item><description>Stale-token recovery on a downstream <c>401 Unauthorized</c> + <c>WWW-Authenticate: Bearer error="invalid_token"</c> (RFC 6750 §3) — the handler invalidates the cached token and retries once with a freshly-minted one (verified by a different jti on attempt 2).</description></item>
/// </list>
///
/// <para>The downstream is an in-process minimal-API app routed through
/// <see cref="TestServer"/> — no port binding, no certificate dance, deterministic
/// shutdown via the test's <c>await using</c> block.</para>
/// </summary>
[Collection(IntegrationTestCollection.Name)]
public class ServiceTokenClientIntegrationTests(AppHostFixture fixture) : IntegrationTestBase(fixture)
{
    private const string AdminEmail = "email@email.com";
    private const string AdminPassword = "Pa5$word123-dev";
    private const string MockAudience = "mock-resource";
    private const string MockScope = "scope.x";

    [Fact]
    public async Task TypedClient_TwoSequentialCalls_HitAuthServiceOnce_DownstreamSeesSameToken()
    {
        // ── arrange: admin provisions a client + (audience, scope) tuple ─────────────
        var (clientId, clientSecret) = await CreateClientAsync();

        // ── arrange: stub downstream that records every Authorization header ─────────
        await using var downstream = await StartMockResourceAsync(_ => Results.Ok(new { ok = true }));

        // ── arrange: TokenClientLib pointed at the real auth service, downstream via TestServer
        var services = BuildConsumerServices(clientId, clientSecret, downstream.Handler);
        await using var sp = services.BuildServiceProvider();
        var factory = sp.GetRequiredService<IHttpClientFactory>();

        // ── act: call the typed client twice in quick succession ─────────────────────
        var http = factory.CreateClient("downstream");
        var r1 = await http.GetAsync("/items");
        var r2 = await http.GetAsync("/items");

        // ── assert: both downstream calls succeeded ──────────────────────────────────
        r1.StatusCode.Should().Be(HttpStatusCode.OK);
        r2.StatusCode.Should().Be(HttpStatusCode.OK);

        // ── assert: downstream saw exactly 2 requests, both with Bearer headers ──────
        downstream.RecordedRequests.Should().HaveCount(2);
        downstream.RecordedRequests[0].BearerToken.Should().NotBeNullOrWhiteSpace(
            because: "the handler must stamp Authorization: Bearer on the very first outgoing call.");
        downstream.RecordedRequests[1].BearerToken.Should().NotBeNullOrWhiteSpace();

        // ── assert: same jti = cache hit, no extra /oauth/token round-trip ───────────
        // If the second call refetched, we'd see a fresh jti — and a quietly more expensive
        // consumer (one /oauth/token hit per outgoing call would be a regression of the whole
        // cache + RefreshAtFractionOfLifetime design).
        var jti1 = ReadJti(downstream.RecordedRequests[0].BearerToken!);
        var jti2 = ReadJti(downstream.RecordedRequests[1].BearerToken!);
        jti1.Should().Be(jti2,
            because: "the second call must hit the in-memory cache; otherwise we'd see a fresh jti " +
                     "and the auth service would have been bothered for nothing.");
    }

    [Fact]
    public async Task TypedClient_DownstreamFirst401InvalidToken_HandlerInvalidatesAndRetriesWithFreshToken()
    {
        // ── arrange: admin provisions a client + scope tuple ─────────────────────────
        var (clientId, clientSecret) = await CreateClientAsync();

        // ── arrange: stub returns 401+invalid_token on attempt 1, 200 on attempt 2 ──
        await using var downstream = await StartMockResourceAsync(
            callCount => Results.Ok(new { ok = true, call = callCount }),
            attach401InvalidTokenHintOnFirstCall: true);

        // ── arrange: TokenClientLib pointed at the real auth service ─────────────────
        var services = BuildConsumerServices(clientId, clientSecret, downstream.Handler);
        await using var sp = services.BuildServiceProvider();
        var factory = sp.GetRequiredService<IHttpClientFactory>();

        // ── act: single typed-client call. The handler does the invalidate-and-retry
        // internally — the caller never sees the 401, only the recovered 200.
        var http = factory.CreateClient("downstream");
        var response = await http.GetAsync("/items");

        // ── assert: the retry produced a 200; the caller sees the recovered response ─
        response.StatusCode.Should().Be(HttpStatusCode.OK,
            because: "an RFC 6750 invalid_token hint on a downstream 401 is exactly the case the handler is built to recover from.");

        // ── assert: downstream saw 2 outgoing requests; jti on attempt 2 differs ────
        downstream.RecordedRequests.Should().HaveCount(2,
            because: "the handler must invalidate the cached token and retry exactly once.");
        var jti1 = ReadJti(downstream.RecordedRequests[0].BearerToken!);
        var jti2 = ReadJti(downstream.RecordedRequests[1].BearerToken!);
        jti2.Should().NotBe(jti1,
            because: "Invalidate-then-retry must actually mint a fresh token — sending the same stale " +
                     "token a second time would defeat the entire stale-token-recovery design.");
    }

    // ── helpers ──────────────────────────────────────────────────────────────────────

    /// <summary>
    /// Logs in as the seeded admin and POSTs a fresh <c>Clients</c> row with exactly one
    /// (audience, scope) tuple. Returns the plaintext secret (one-time-display) so the
    /// caller can hand it to <see cref="ServiceTokenClientOptions"/>.
    /// </summary>
    private async Task<(string clientId, string clientSecret)> CreateClientAsync()
    {
        var adminToken = await AuthenticateAdminAsync();
        var clientId = $"scenario15-{Guid.NewGuid():N}";

        AuthClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", adminToken);
        var createResp = await AuthClient.PostAsJsonAsync(
            "/api/Admin/clients",
            new AdminCreateClientDto
            {
                Id = clientId,
                Name = "Scenario 15 typed-client",
                Description = "Provisioned by the TokenClientLib end-to-end scenario.",
                Scopes = new List<AdminClientScopeDto>
                {
                    new() { Audience = MockAudience, Scope = MockScope },
                },
            });
        createResp.StatusCode.Should().Be(HttpStatusCode.Created,
            because: "the test relies on the admin endpoint creating a real Clients row to back the token request.");

        var rawSecret = (await createResp.Content.ReadFromJsonAsync<ClientCreatedResponse>())!.ClientSecret!;
        AuthClient.DefaultRequestHeaders.Authorization = null;
        return (clientId, rawSecret);
    }

    private async Task<string> AuthenticateAdminAsync()
    {
        var resp = await AuthClient.PostAsJsonAsync(
            "/api/Authentication/authenticate",
            new AuthenticationDto { Email = AdminEmail, Password = AdminPassword });
        resp.IsSuccessStatusCode.Should().BeTrue();

        var body = await resp.Content.ReadFromJsonAsync<AuthenticationResponse>()
            ?? throw new InvalidOperationException("Authentication response body deserialised to null.");
        return body.Token?.Value ?? throw new InvalidOperationException("Authentication response carried no token.");
    }

    /// <summary>
    /// Builds a fresh <see cref="IServiceCollection"/> configured to drive the
    /// TokenClientLib end-to-end:
    /// <list type="bullet">
    ///   <item><description>Provider points at the running auth service (URL pulled from the fixture's <see cref="HttpClient"/>).</description></item>
    ///   <item><description>Typed <c>"downstream"</c> client routes through <paramref name="downstreamHandler"/> so calls land in the in-process stub.</description></item>
    /// </list>
    /// </summary>
    private IServiceCollection BuildConsumerServices(
        string clientId, string clientSecret, HttpMessageHandler downstreamHandler)
    {
        var services = new ServiceCollection();
        services.AddLogging(b => b.SetMinimumLevel(LogLevel.Warning));

        // The fixture serves the auth service over HTTP — flip RequireHttpsMetadata off so
        // the discovery doc / token endpoint URLs aren't rejected.
        var authBaseUrl = AuthClient.BaseAddress!.AbsoluteUri.TrimEnd('/');
        var config = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["AuthenticationService:Authority"] = authBaseUrl,
                ["AuthenticationService:ClientId"] = clientId,
                ["AuthenticationService:ClientSecret"] = clientSecret,
                ["AuthenticationService:RequireHttpsMetadata"] = "false",
            })
            .Build();

        services.AddAuthenticationServiceTokenClient(config.GetSection("AuthenticationService"));

        // The typed client's BaseAddress is irrelevant — TestServer ignores host/scheme and
        // dispatches based on the request path. We only need it set so HttpClient accepts
        // relative URIs in the test bodies.
        services
            .AddHttpClient("downstream", c => c.BaseAddress = new Uri("http://mock-resource.test"))
            .AddServiceToken(MockAudience, MockScope)
            .ConfigurePrimaryHttpMessageHandler(() => downstreamHandler);

        return services;
    }

    private static string ReadJti(string bearerToken)
    {
        var jwt = new JwtSecurityTokenHandler().ReadJwtToken(bearerToken);
        return jwt.Id;
    }

    /// <summary>
    /// Spins up a minimal-API ASP.NET Core app behind <see cref="TestServer"/> and returns
    /// the bits the test needs: an <see cref="HttpMessageHandler"/> for the typed-client's
    /// primary-handler slot, a thread-safe recorded-requests view, and a disposal hook.
    ///
    /// <para>The <paramref name="responder"/> is invoked for every call (with the 1-based
    /// call index), <em>unless</em> <paramref name="attach401InvalidTokenHintOnFirstCall"/>
    /// is true and this is the first call — in which case the endpoint returns 401 with
    /// the RFC 6750 invalid_token hint, exactly what triggers the handler's retry path.</para>
    /// </summary>
    private static async Task<MockResource> StartMockResourceAsync(
        Func<int, IResult> responder,
        bool attach401InvalidTokenHintOnFirstCall = false)
    {
        var recorded = new List<RecordedRequest>();
        var callCount = 0;

        var builder = WebApplication.CreateBuilder();
        builder.WebHost.UseTestServer();
        builder.Logging.SetMinimumLevel(LogLevel.Warning);  // silence noisy default startup logs
        var app = builder.Build();

        app.MapGet("/items", (HttpContext ctx) =>
        {
            var bearer = ctx.Request.Headers.Authorization.FirstOrDefault();
            var token = ParseBearer(bearer);
            var thisCall = Interlocked.Increment(ref callCount);
            lock (recorded) { recorded.Add(new RecordedRequest(token)); }

            if (attach401InvalidTokenHintOnFirstCall && thisCall == 1)
            {
                // Set the exact wire shape the handler is documented to react to. Setting
                // headers + status manually (rather than via Results.Unauthorized()) is the
                // only way to attach WWW-Authenticate to a minimal-API result.
                ctx.Response.StatusCode = (int)HttpStatusCode.Unauthorized;
                ctx.Response.Headers["WWW-Authenticate"] = "Bearer error=\"invalid_token\"";
                return Results.Empty;
            }
            return responder(thisCall);
        });

        await app.StartAsync();
        var server = app.GetTestServer();
        return new MockResource(app, server.CreateHandler(), recorded);
    }

    private static string? ParseBearer(string? authorizationHeader)
    {
        if (string.IsNullOrEmpty(authorizationHeader)) return null;
        var parts = authorizationHeader.Split(' ', 2);
        return parts.Length == 2 && string.Equals(parts[0], "Bearer", StringComparison.OrdinalIgnoreCase)
            ? parts[1]
            : null;
    }

    private sealed record RecordedRequest(string? BearerToken);

    private sealed class MockResource(
        WebApplication app,
        HttpMessageHandler handler,
        List<RecordedRequest> recorded) : IAsyncDisposable
    {
        public HttpMessageHandler Handler => handler;

        public IReadOnlyList<RecordedRequest> RecordedRequests
        {
            get { lock (recorded) { return recorded.ToList(); } }
        }

        public async ValueTask DisposeAsync()
        {
            handler.Dispose();
            await app.StopAsync();
            await app.DisposeAsync();
        }
    }
}
