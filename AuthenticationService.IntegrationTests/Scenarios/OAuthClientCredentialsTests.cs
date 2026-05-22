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
/// Scenario 13 — Admin creates client → OAuth token issued → JWT shape verified. End-to-end
/// for the Phase 1 s2s surface against real MySQL. Load-bearing — a regression means
/// consumers can't get tokens and everything downstream breaks.
/// </summary>
[Collection(IntegrationTestCollection.Name)]
public class OAuthClientCredentialsTests(AppHostFixture fixture) : IntegrationTestBase(fixture)
{
    private const string AdminEmail = "email@email.com";
    private const string AdminPassword = "Pa5$word123-dev";

    [Fact]
    public async Task AdminCreatesClient_TokenEndpointIssuesServiceJwt_WithExpectedClaimShape()
    {
        // arrange
        var adminToken = await AuthenticateAsync(AdminEmail, AdminPassword);

        var clientId = $"test-client-{Guid.NewGuid():N}";
        AuthClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", adminToken);

        // act — phase 1: admin creates client
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

        // assert — phase 1
        createResp.StatusCode.Should().Be(HttpStatusCode.Created,
            because: "admin-creates-client with a fresh id + valid scopes must succeed.");

        var created = await createResp.Content.ReadFromJsonAsync<ClientCreatedResponse>();
        created.Should().NotBeNull();
        created!.ClientSecret.Should().NotBeNullOrEmpty(
            because: "the response must carry the plaintext secret (one-time display) for the admin to capture.");
        var rawSecret = created.ClientSecret;

        await using (var db = await CreateDbContextAsync())
        {
            var dbClient = await db.Clients.SingleAsync(c => c.Id == clientId);
            dbClient.ClientSecretHash.Should().NotBe(rawSecret,
                because: "DB must store only the hash; the plaintext is response-only.");
            dbClient.IsDisabled.Should().BeFalse();
            (await db.ClientScopes.CountAsync(s => s.ClientId == clientId))
                .Should().Be(2, because: "both initial scopes must be persisted.");
        }

        // Token endpoint is anonymous + uses Basic auth — drop the admin bearer.
        AuthClient.DefaultRequestHeaders.Authorization = null;

        // act — phase 2: token endpoint issues service JWT
        var tokenForm = new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["grant_type"] = "client_credentials",
            ["client_id"] = clientId,
            ["client_secret"] = rawSecret,
            ["audience"] = "inventory-api",
            ["scope"] = "inventory.read inventory.write",
        });
        var tokenResp = await AuthClient.PostAsync("/oauth/token", tokenForm);

        // assert — phase 2
        tokenResp.IsSuccessStatusCode.Should().BeTrue(
            because: "valid credentials + authorised scopes must yield a token.");

        var tokenBody = await tokenResp.Content.ReadFromJsonAsync<OAuthTokenResponse>();
        tokenBody.Should().NotBeNull();
        tokenBody!.AccessToken.Should().NotBeNullOrEmpty();
        tokenBody.TokenType.Should().Be("Bearer");
        tokenBody.ExpiresIn.Should().BeGreaterThan(0);
        tokenBody.Scope.Should().Be("inventory.read inventory.write",
            because: "the granted-scope field echoes the requested scopes when all were authorised.");

        var jwt = new JwtSecurityTokenHandler().ReadJwtToken(tokenBody.AccessToken);
        jwt.Subject.Should().Be(clientId,
            because: "sub on a service token is the client_id, not a user id.");
        jwt.Audiences.Should().Contain("inventory-api",
            because: "aud reflects the requested audience.");
        jwt.Claims.Should().Contain(c => c.Type == ClaimConstants.ClientId && c.Value == clientId);
        jwt.Claims.Should().Contain(c => c.Type == ClaimConstants.Scope && c.Value == "inventory.read inventory.write");
        jwt.Claims.Should().NotContain(c => c.Type == ClaimConstants.Email,
            because: "service tokens deliberately omit user claims — consumers distinguish kinds by their absence.");

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
