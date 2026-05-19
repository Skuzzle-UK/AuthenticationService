using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using AuthenticationService.Shared.Dtos;
using AuthenticationService.Shared.Dtos.Response;
using AwesomeAssertions;

namespace AuthenticationService.IntegrationTests.Scenarios;

/// <summary>
/// <para><b>Scenario 14 — Client requests a scope it doesn't own → 400 invalid_scope.</b></para>
///
/// <para>Complements Scenario 13 by pinning the negative path — the bit that makes
/// the scope system load-bearing. A client is created with only <c>inventory.read</c>;
/// requesting <c>inventory.write</c> on the same client must be rejected at the token
/// endpoint, before any JWT is issued.</para>
///
/// <para>Asserts:</para>
/// <list type="bullet">
///   <item><description>Requesting an unauthorised scope returns <c>invalid_scope</c> with no token.</description></item>
///   <item><description>Requesting an authorised scope on the same client still works (so the failure is per-scope, not a blanket block).</description></item>
/// </list>
/// </summary>
[Collection(IntegrationTestCollection.Name)]
public class OAuthScopeAuthorizationTests(AppHostFixture fixture) : IntegrationTestBase(fixture)
{
    private const string AdminEmail = "email@email.com";
    private const string AdminPassword = "Pa5$word123-dev";

    [Fact]
    public async Task UnauthorisedScopeRequest_ReturnsInvalidScope_AuthorisedScopeStillWorks()
    {
        // arrange — admin creates a client with ONLY inventory.read on inventory-api.
        var adminToken = await AuthenticateAsync(AdminEmail, AdminPassword);
        var clientId = $"scope-test-{Guid.NewGuid():N}";

        AuthClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", adminToken);
        var createResp = await AuthClient.PostAsJsonAsync(
            "/api/Admin/clients",
            new AdminCreateClientDto
            {
                Id = clientId,
                Name = "Scope test client",
                Scopes = new List<AdminClientScopeDto>
                {
                    new() { Audience = "inventory-api", Scope = "inventory.read" },
                },
            });
        createResp.StatusCode.Should().Be(HttpStatusCode.Created);
        var rawSecret = (await createResp.Content.ReadFromJsonAsync<ClientCreatedResponse>())!.ClientSecret;

        AuthClient.DefaultRequestHeaders.Authorization = null;

        // ── act 1: request a scope the client doesn't have ───────────────────────────
        var deniedResp = await AuthClient.PostAsync(
            "/oauth/token",
            new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["grant_type"] = "client_credentials",
                ["client_id"] = clientId,
                ["client_secret"] = rawSecret,
                ["audience"] = "inventory-api",
                ["scope"] = "inventory.write",
            }));

        deniedResp.StatusCode.Should().Be(HttpStatusCode.BadRequest,
            because: "requesting a scope the client doesn't own must fail at the token endpoint, before any JWT is issued.");

        var deniedBody = await deniedResp.Content.ReadFromJsonAsync<OAuthErrorResponse>();
        deniedBody!.Error.Should().Be("invalid_scope",
            because: "RFC 6749 §5.2 — unauthorised scope is exactly this error code.");

        // ── act 2: request a scope the client DOES have on the same client ──────────
        var allowedResp = await AuthClient.PostAsync(
            "/oauth/token",
            new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["grant_type"] = "client_credentials",
                ["client_id"] = clientId,
                ["client_secret"] = rawSecret,
                ["audience"] = "inventory-api",
                ["scope"] = "inventory.read",
            }));

        allowedResp.IsSuccessStatusCode.Should().BeTrue(
            because: "the invalid_scope denial above must be per-requested-scope, not a blanket block on the client.");

        var allowedBody = await allowedResp.Content.ReadFromJsonAsync<OAuthTokenResponse>();
        allowedBody!.AccessToken.Should().NotBeNullOrEmpty();
        allowedBody.Scope.Should().Be("inventory.read");
    }

    [Fact]
    public async Task PartialScopeAuthorisation_AllOrNothing_NoToken()
    {
        // Scope grants are atomic: if one of the requested scopes is missing, the whole
        // request is rejected. There's no "give me what you can" partial-grant mode.
        var adminToken = await AuthenticateAsync(AdminEmail, AdminPassword);
        var clientId = $"partial-scope-{Guid.NewGuid():N}";

        AuthClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", adminToken);
        var createResp = await AuthClient.PostAsJsonAsync(
            "/api/Admin/clients",
            new AdminCreateClientDto
            {
                Id = clientId,
                Name = "Partial-scope test client",
                Scopes = new List<AdminClientScopeDto>
                {
                    new() { Audience = "inventory-api", Scope = "inventory.read" },
                    // Deliberately NO inventory.write.
                },
            });
        var rawSecret = (await createResp.Content.ReadFromJsonAsync<ClientCreatedResponse>())!.ClientSecret;
        AuthClient.DefaultRequestHeaders.Authorization = null;

        var resp = await AuthClient.PostAsync(
            "/oauth/token",
            new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["grant_type"] = "client_credentials",
                ["client_id"] = clientId,
                ["client_secret"] = rawSecret,
                ["audience"] = "inventory-api",
                ["scope"] = "inventory.read inventory.write",
            }));

        resp.StatusCode.Should().Be(HttpStatusCode.BadRequest);
        var body = await resp.Content.ReadFromJsonAsync<OAuthErrorResponse>();
        body!.Error.Should().Be("invalid_scope",
            because: "even with one valid scope among many requested, the missing scope must reject the whole request.");
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
