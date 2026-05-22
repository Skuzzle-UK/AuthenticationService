using System.IdentityModel.Tokens.Jwt;
using System.Net.Http.Json;
using System.Text.Json.Serialization;
using AwesomeAssertions;
using Microsoft.IdentityModel.Tokens;

namespace AuthenticationService.IntegrationTests.Scenarios;

/// <summary>
/// Scenario 7 — JWKS / OIDC discovery snapshot. Does the full consumer round-trip:
/// fetches <c>/.well-known/openid-configuration</c> + <c>/.well-known/jwks.json</c>, then
/// validates a real auth-service-issued JWT using only the published wire contract. A
/// regression here (wrong fields, wrong key, mismatched kid) breaks every consumer's
/// JwtBearer middleware — a catastrophic break unit tests would mock away.
/// </summary>
[Collection(IntegrationTestCollection.Name)]
public class WellKnownDiscoveryTests(AppHostFixture fixture) : IntegrationTestBase(fixture)
{
    [Fact]
    public async Task DiscoveryAndJwks_PublishKeysThatValidateRealIssuedJwt()
    {
        // arrange
        var user = await RegisterAndConfirmUserAsync();
        var issuedToken = await LoginAsync(user);
        issuedToken.Value.Should().NotBeNullOrEmpty();

        // act — phase 1: fetch the OIDC discovery document
        var discoveryDoc = await AuthClient.GetFromJsonAsync<OidcDiscoveryDocument>(
            "/.well-known/openid-configuration");

        // assert — phase 1
        discoveryDoc.Should().NotBeNull();
        discoveryDoc!.Issuer.Should().NotBeNullOrEmpty(
            because: "consumers validate the iss claim against this — empty would break every JwtBearer setup.");
        discoveryDoc.JwksUri.Should().Contain("/.well-known/jwks.json",
            because: "consumers fetch the keys from this URL — wrong path would mean no keys, no validation.");
        discoveryDoc.IdTokenSigningAlgValuesSupported.Should().Contain("ES256",
            because: "the auth service signs with ES256 — advertising a different alg here would mean consumers reject every token.");

        // act — phase 2: fetch the JWKS
        var jwksJson = await AuthClient.GetStringAsync("/.well-known/jwks.json");
        var keySet = new JsonWebKeySet(jwksJson);

        // assert — phase 2
        keySet.Keys.Should().NotBeEmpty(
            because: "JWKS must publish at least the active signing key — empty means no consumer can validate any token.");
        keySet.Keys.Should().AllSatisfy(k =>
        {
            k.Kty.Should().Be("EC", because: "ECDSA — RSA would mean a different key shape.");
            k.Crv.Should().Be("P-256", because: "ES256 specifies the P-256 curve.");
            k.Use.Should().Be("sig", because: "these keys are for signature verification, not encryption.");
            k.Alg.Should().Be("ES256", because: "matches the auth service's signing alg.");
            k.Kid.Should().NotBeNullOrEmpty(because: "kid links a JWT's header to the right JWKS key during validation.");
        });

        // act — phase 3: validate the JWT against the published wire contract
        // Validate the JWT using only the published wire contract — exactly what a
        // downstream consumer's JwtBearer middleware would do.
        var validationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidateIssuerSigningKey = true,
            ValidateLifetime = true,
            ValidIssuer = discoveryDoc.Issuer,
            IssuerSigningKeys = keySet.Keys,
            ValidAlgorithms = ["ES256"],
            // Audience-match is the consumer's responsibility; we only assert that
            // signature + issuer + alg + lifetime validate against the wire contract.
            ValidateAudience = false,
            // Don't remap claim names — auth service uses literal "sub" / "sid".
            NameClaimType = "sub",
        };

        var handler = new JwtSecurityTokenHandler { MapInboundClaims = false };
        var principal = handler.ValidateToken(
            issuedToken.Value,
            validationParameters,
            out var validatedToken);

        // assert — phase 3
        principal.Should().NotBeNull(
            because: "the JWKS-published key must validate a JWT issued by the same service. " +
                     "If this fails, consumers cannot validate tokens — total auth-chain failure.");
        validatedToken.Should().NotBeNull();
        principal.FindFirst("sub")?.Value.Should().NotBeNullOrEmpty(
            because: "every issued JWT must carry a sub claim — that's the user identifier consumers act on.");
    }

    /// <summary>
    /// Subset of the OIDC discovery document — only the fields this test needs.
    /// </summary>
    private sealed record OidcDiscoveryDocument(
        [property: JsonPropertyName("issuer")] string Issuer,
        [property: JsonPropertyName("jwks_uri")] string JwksUri,
        [property: JsonPropertyName("id_token_signing_alg_values_supported")]
        IReadOnlyList<string> IdTokenSigningAlgValuesSupported);
}
