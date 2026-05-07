using System.Text.Json;
using AuthenticationService.Services;
using AwesomeAssertions;

namespace AuthenticationService.Tests.Services;

/// <summary>
/// <para><see cref="JwksDocument"/> + <see cref="JwksKey"/> are the wire shape of the
/// <c>/.well-known/jwks.json</c> response. Field-name compatibility with the JSON Web Key
/// spec is non-negotiable — JwtBearer in every consumer service expects exactly these
/// names. The codebase relies on the global <c>JsonNamingPolicy.CamelCase</c> to convert
/// PascalCase → lowercase; tests pin that the conversion produces the spec-required JSON.</para>
/// </summary>
public class JwksDocumentTests
{
    [Fact]
    public void JwksDocument_SerializeWithCamelCasePolicy_ProducesSpecCompliantJson()
    {
        // arrange — single-key document mirroring what the controller serves.
        var doc = new JwksDocument(new[]
        {
            new JwksKey(
                Kty: "EC",
                Crv: "P-256",
                X: "x-base64url",
                Y: "y-base64url",
                Use: "sig",
                Alg: "ES256",
                Kid: "thumbprint")
        });
        var options = new JsonSerializerOptions { PropertyNamingPolicy = JsonNamingPolicy.CamelCase };

        // act
        var json = JsonSerializer.Serialize(doc, options);

        // assert — pin every spec-required field name exactly. JwtBearer / OIDC consumers
        // parse case-sensitively, so "Kty" instead of "kty" would silently break validation.
        json.Should().Contain("\"keys\":");
        json.Should().Contain("\"kty\":\"EC\"");
        json.Should().Contain("\"crv\":\"P-256\"");
        json.Should().Contain("\"x\":\"x-base64url\"");
        json.Should().Contain("\"y\":\"y-base64url\"");
        json.Should().Contain("\"use\":\"sig\"");
        json.Should().Contain("\"alg\":\"ES256\"");
        json.Should().Contain("\"kid\":\"thumbprint\"");
    }

    [Fact]
    public void JwksDocument_SerializesEmptyKeyList_AsEmptyArray()
    {
        // arrange — degenerate but legal: a key provider that's loaded zero keys (during
        // provisioning, before any key is in the directory). The controller must still
        // produce structurally-valid JSON.
        var doc = new JwksDocument(Array.Empty<JwksKey>());
        var options = new JsonSerializerOptions { PropertyNamingPolicy = JsonNamingPolicy.CamelCase };

        // act
        var json = JsonSerializer.Serialize(doc, options);

        // assert
        json.Should().Be("{\"keys\":[]}");
    }

    [Fact]
    public void JwksDocument_RecordsAreImmutableAndStructurallyEqual()
    {
        // arrange — record semantics: two same-valued JwksKey records compare equal so
        // the cached document on EcdsaKeyProvider can be safely shared without mutation
        // concerns.
        var k1 = new JwksKey("EC", "P-256", "x", "y", "sig", "ES256", "kid");
        var k2 = new JwksKey("EC", "P-256", "x", "y", "sig", "ES256", "kid");
        var doc1 = new JwksDocument(new[] { k1 });
        var doc2 = new JwksDocument(new[] { k2 });

        // act / assert — JwksKey records compare structurally-equal but JwksDocument's
        // single property is the array reference, which uses reference equality. So we
        // pin that the keys themselves are structurally equal even when wrapped in two
        // different documents.
        k1.Should().Be(k2);
        doc1.Keys[0].Should().Be(doc2.Keys[0]);
    }

    [Fact]
    public void JwksKey_AllFieldsPopulated_RoundTripsThroughJson()
    {
        // arrange — round-trip: serialize then deserialize and verify every field comes
        // back. Catches a regression where one of the field names diverges between
        // serialization and deserialization.
        var original = new JwksKey("EC", "P-256", "AAA", "BBB", "sig", "ES256", "thumb");
        var options = new JsonSerializerOptions { PropertyNamingPolicy = JsonNamingPolicy.CamelCase };

        // act
        var json = JsonSerializer.Serialize(original, options);
        var roundTripped = JsonSerializer.Deserialize<JwksKey>(json, options);

        // assert
        roundTripped.Should().Be(original);
    }
}
