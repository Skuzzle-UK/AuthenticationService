using System.IdentityModel.Tokens.Jwt;
using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using AuthenticationService.Shared.Constants;
using AuthenticationService.Shared.Dtos;
using AuthenticationService.Shared.Dtos.Response;
using AwesomeAssertions;
using Microsoft.EntityFrameworkCore;

namespace AuthenticationService.IntegrationTests.Scenarios;

/// <summary>
/// <para><b>Scenario 13 — Admin creates client → OAuth token issued → JWT shape verified.</b></para>
///
/// <para>End-to-end exercise of the Phase 1 s2s surface against real MySQL:</para>
/// <list type="number">
///   <item><description>Admin authenticates against the user-token endpoint.</description></item>
///   <item><description>Admin POSTs <c>/api/Admin/clients</c> with an initial scope list.</description></item>
///   <item><description>Response carries the plaintext client_secret (one-time display).</description></item>
///   <item><description>DB row exists; secret is stored as a hash (not plaintext).</description></item>
///   <item><description>Anyone POSTs <c>/oauth/token</c> with the client credentials + form-encoded grant.</description></item>
///   <item><description>Response is a JWT with the expected service-token claim shape.</description></item>
/// </list>
///
/// <para>This is the load-bearing assertion for the Phase 1 service-to-service flow.
/// A regression here means consumers can't get tokens; everything downstream breaks.</para>
/// </summary>
[Collection(IntegrationTestCollection.Name)]
public class OAuthClientCredentialsTests(AppHostFixture fixture) : IntegrationTestBase(fixture)
{
    private const string AdminEmail = "email@email.com";
    private const string AdminPassword = "Pa5$word123-dev";

    [Fact]
    public async Task AdminCreatesClient_TokenEndpointIssuesServiceJwt_WithExpectedClaimShape()
    {
        // ── act 1: log in as the seeded admin ────────────────────────────────────────
        var adminToken = await AuthenticateAsync(AdminEmail, AdminPassword);

        // ── act 2: admin creates a client with initial scopes ────────────────────────
        var clientId = $"test-client-{Guid.NewGuid():N}";
        AuthClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", adminToken);

        var createResp = await AuthClient.PostAsJsonAsync(
            "/api/Admin/clients",
            new AdminCreateClientDto
            {
                Id = clientId,
                Name = "Integration test client",
                Description = "scenario 13",
                Scopes = new List<AdminClientScopeDto>
                {
                    new() { Audience = "inventory-api", Scope = "inventory.read" },
                    new() { Audience = "inventory-api", Scope = "inventory.write" },
                },
            });

        createResp.StatusCode.Should().Be(HttpStatusCode.Created,
            because: "admin-creates-client with a fresh id + valid scopes must succeed.");

        var created = await createResp.Content.ReadFromJsonAsync<ClientCreatedResponse>();
        created.Should().NotBeNull();
        created!.ClientSecret.Should().NotBeNullOrEmpty(
            because: "the response must carry the plaintext secret (one-time display) for the admin to capture.");
        var rawSecret = created.ClientSecret;

        // ── assert DB: row exists, secret is hashed not plaintext ────────────────────
        await using (var db = await CreateDbContextAsync())
        {
            var dbClient = await db.Clients.SingleAsync(c => c.Id == clientId);
            dbClient.ClientSecretHash.Should().NotBe(rawSecret,
                because: "DB must store only the hash; the plaintext is response-only.");
            dbClient.IsDisabled.Should().BeFalse();
            (await db.ClientScopes.CountAsync(s => s.ClientId == clientId))
                .Should().Be(2, because: "both initial scopes must be persisted.");
        }

        // ── act 3: client exchanges credentials at /oauth/token ──────────────────────
        // Drop the admin bearer header — token endpoint is anonymous + uses Basic auth.
        AuthClient.DefaultRequestHeaders.Authorization = null;

        var tokenForm = new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["grant_type"] = "client_credentials",
            ["client_id"] = clientId,
            ["client_secret"] = rawSecret,
            ["audience"] = "inventory-api",
            ["scope"] = "inventory.read inventory.write",
        });
        var tokenResp = await AuthClient.PostAsync("/oauth/token", tokenForm);

        tokenResp.IsSuccessStatusCode.Should().BeTrue(
            because: "valid credentials + authorised scopes must yield a token.");

        var tokenBody = await tokenResp.Content.ReadFromJsonAsync<OAuthTokenResponse>();
        tokenBody.Should().NotBeNull();
        tokenBody!.AccessToken.Should().NotBeNullOrEmpty();
        tokenBody.TokenType.Should().Be("Bearer");
        tokenBody.ExpiresIn.Should().BeGreaterThan(0);
        tokenBody.Scope.Should().Be("inventory.read inventory.write",
            because: "the granted-scope field echoes the requested scopes when all were authorised.");

        // ── assert JWT claim shape ───────────────────────────────────────────────────
        var jwt = new JwtSecurityTokenHandler().ReadJwtToken(tokenBody.AccessToken);
        jwt.Subject.Should().Be(clientId,
            because: "sub on a service token is the client_id, not a user id.");
        jwt.Audiences.Should().Contain("inventory-api",
            because: "aud reflects the requested audience.");
        jwt.Claims.Should().Contain(c => c.Type == ClaimConstants.ClientId && c.Value == clientId);
        jwt.Claims.Should().Contain(c => c.Type == ClaimConstants.Scope && c.Value == "inventory.read inventory.write");
        jwt.Claims.Should().NotContain(c => c.Type == ClaimConstants.Email,
            because: "service tokens deliberately omit user claims — consumers distinguish kinds by their absence.");

        // ── assert: LastUsedAt was stamped ───────────────────────────────────────────
        await using (var db = await CreateDbContextAsync())
        {
            var dbClient = await db.Clients.AsNoTracking().SingleAsync(c => c.Id == clientId);
            dbClient.LastUsedAt.Should().NotBeNull(
                because: "successful token issuance must stamp LastUsedAt for admin visibility into client activity.");
        }
    }

    private async Task<string> AuthenticateAsync(string email, string password)
    {
        var resp = await AuthClient.PostAsJsonAsync(
            "/api/Authentication/authenticate",
            new AuthenticationDto { Email = email, Password = password });
        resp.IsSuccessStatusCode.Should().BeTrue();

        var body = await resp.Content.ReadFromJsonAsync<AuthenticationResponse>()
            ?? throw new InvalidOperationException("Authentication response body deserialised to null.");
        return body.Token?.Value ?? throw new InvalidOperationException("Authentication response carried no token.");
    }
}
