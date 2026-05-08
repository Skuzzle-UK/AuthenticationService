using System.IdentityModel.Tokens.Jwt;
using System.Net.Http.Json;
using System.Text.Json.Serialization;
using AwesomeAssertions;
using Microsoft.IdentityModel.Tokens;

namespace AuthenticationService.IntegrationTests.Scenarios;

/// <summary>
/// <para><b>Scenario 7 — JWKS / OIDC discovery snapshot.</b></para>
///
/// <para>The auth service publishes its identity-provider contract at two well-known
/// URLs:</para>
/// <list type="bullet">
///   <item><description><c>/.well-known/openid-configuration</c> — the discovery doc consumers point JwtBearer's <c>Authority</c> at to auto-configure validation.</description></item>
///   <item><description><c>/.well-known/jwks.json</c> — the public signing keys consumers fetch to validate JWT signatures locally.</description></item>
/// </list>
///
/// <para>This scenario does the full consumer round-trip: fetches both endpoints,
/// verifies the wire shape, then uses the published JWKS to validate a real JWT
/// issued by the auth service. If any of that breaks — wrong field names, wrong
/// signing key in JWKS, mismatched <c>kid</c> between issued JWT and published key,
/// missing OIDC fields — consumers' JwtBearer middleware would reject every token,
/// effectively bringing down the platform's auth chain. Catastrophic regression that
/// the unit tests can mock away but a real wire test catches every time.</para>
/// </summary>
[Collection(IntegrationTestCollection.Name)]
public class WellKnownDiscoveryTests(AppHostFixture fixture) : IntegrationTestBase(fixture)
{
    [Fact]
    public async Task DiscoveryAndJwks_PublishKeysThatValidateRealIssuedJwt()
    {
        // arrange — get a real JWT from a fresh login. The point of this scenario is
        // that the JWKS publishes keys capable of validating tokens the service is
        // actually issuing, so we need a live token to verify against.
        var user = await RegisterAndConfirmUserAsync();
        var issuedToken = await LoginAsync(user);
        issuedToken.Value.Should().NotBeNullOrEmpty();

        // act 1 — fetch the OIDC discovery document. JWKS-uri-by-discovery is how
        // consumers point JwtBearer's Authority at the auth service; if the doc shape
        // is wrong, JwtBearer can't auto-configure.
        var discoveryDoc = await AuthClient.GetFromJsonAsync<OidcDiscoveryDocument>(
            "/.well-known/openid-configuration");

        // assert 1 — discovery doc has the three load-bearing fields.
        discoveryDoc.Should().NotBeNull();
        discoveryDoc!.Issuer.Should().NotBeNullOrEmpty(
            because: "consumers validate the iss claim against this — empty would break every JwtBearer setup.");
        discoveryDoc.JwksUri.Should().Contain("/.well-known/jwks.json",
            because: "consumers fetch the keys from this URL — wrong path would mean no keys, no validation.");
        discoveryDoc.IdTokenSigningAlgValuesSupported.Should().Contain("ES256",
            because: "the auth service signs with ES256 — advertising a different alg here would mean consumers reject every token.");

        // act 2 — fetch the JWKS itself.
        var jwksJson = await AuthClient.GetStringAsync("/.well-known/jwks.json");
        var keySet = new JsonWebKeySet(jwksJson);

        // assert 2 — at least one key, and every key advertises the right cryptographic
        // shape. The auth service uses ES256 (ECDSA on the P-256 curve).
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

        // act 3 — the actual contract test. Validate the JWT we got from /authenticate
        // using only the published JWKS keys + discovery's issuer. This is exactly what
        // a downstream consumer's JwtBearer middleware would do.
        var validationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidateIssuerSigningKey = true,
            ValidateLifetime = true,
            ValidIssuer = discoveryDoc.Issuer,
            IssuerSigningKeys = keySet.Keys,
            ValidAlgorithms = ["ES256"],
            // We don't validate audience here — the discovery doc doesn't advertise it,
            // and matching audience is the consumer's responsibility (each microservice
            // will configure its own ValidAudience). What this test asserts is that
            // *signature + issuer + alg + lifetime* validate cleanly using only the
            // public-facing wire contract.
            ValidateAudience = false,
            // Don't remap the JWT claim names — auth service uses literal "sub" / "sid".
            NameClaimType = "sub",
        };

        var handler = new JwtSecurityTokenHandler { MapInboundClaims = false };
        var principal = handler.ValidateToken(
            issuedToken.Value,
            validationParameters,
            out var validatedToken);

        // assert 3 — validation succeeded; we got a populated principal carrying the
        // user's sub claim back.
        principal.Should().NotBeNull(
            because: "the JWKS-published key must validate a JWT issued by the same service. " +
                     "If this fails, consumers cannot validate tokens — total auth-chain failure.");
        validatedToken.Should().NotBeNull();
        principal.FindFirst("sub")?.Value.Should().NotBeNullOrEmpty(
            because: "every issued JWT must carry a sub claim — that's the user identifier consumers act on.");
    }

    /// <summary>
    /// Subset of the OIDC discovery document the auth service publishes. The full spec
    /// has more fields; we only deserialise the three this test needs.
    /// </summary>
    private sealed record OidcDiscoveryDocument(
        [property: JsonPropertyName("issuer")] string Issuer,
        [property: JsonPropertyName("jwks_uri")] string JwksUri,
        [property: JsonPropertyName("id_token_signing_alg_values_supported")]
        IReadOnlyList<string> IdTokenSigningAlgValuesSupported);
}
