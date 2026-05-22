using System.Text.Json;
using AuthenticationService.Services;
using AwesomeAssertions;

namespace AuthenticationService.Tests.Services;

/// <summary>
/// Pins JWKS field names are spec-compliant after the global CamelCase JSON policy runs —
/// JwtBearer in every consumer service parses case-sensitively.
/// </summary>
public class JwksDocumentTests
{
    [Fact]
    public void JwksDocument_SerializeWithCamelCasePolicy_ProducesSpecCompliantJson()
    {
        // arrange
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

        // assert
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
        // arrange — degenerate but legal: a provider that's loaded zero keys must still produce valid JSON.
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
        // arrange
        var k1 = new JwksKey("EC", "P-256", "x", "y", "sig", "ES256", "kid");
        var k2 = new JwksKey("EC", "P-256", "x", "y", "sig", "ES256", "kid");
        var doc1 = new JwksDocument(new[] { k1 });
        var doc2 = new JwksDocument(new[] { k2 });

        // act + assert
        k1.Should().Be(k2);
        doc1.Keys[0].Should().Be(doc2.Keys[0]);
    }

    [Fact]
    public void JwksKey_AllFieldsPopulated_RoundTripsThroughJson()
    {
        // arrange
        var original = new JwksKey("EC", "P-256", "AAA", "BBB", "sig", "ES256", "thumb");
        var options = new JsonSerializerOptions { PropertyNamingPolicy = JsonNamingPolicy.CamelCase };

        // act
        var json = JsonSerializer.Serialize(original, options);
        var roundTripped = JsonSerializer.Deserialize<JwksKey>(json, options);

        // assert
        roundTripped.Should().Be(original);
    }
}
