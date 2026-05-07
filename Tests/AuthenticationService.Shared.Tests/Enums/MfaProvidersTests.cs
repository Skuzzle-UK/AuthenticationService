using AuthenticationService.Shared.Enums;
using AwesomeAssertions;

namespace AuthenticationService.Shared.Tests.Enums;

/// <summary>
/// <para><see cref="MfaProviders"/> is serialized into JSON responses and into the
/// <see cref="Dtos.AuthenticationDto.MfaProvider"/> request body — it's a wire enum.
/// The numeric values, when not explicitly assigned, are stable in declaration order;
/// any reordering of the enum members would silently change the wire encoding for any
/// integer-mode JSON converter. The codebase configures <c>JsonStringEnumConverter</c>
/// globally so we serialize as names — these tests pin both the names and the explicit
/// member set so reordering or renaming is caught.</para>
/// </summary>
public class MfaProvidersTests
{
    [Fact]
    public void MfaProviders_DeclaresExpectedMembers_AndOnlyThose()
    {
        // arrange / act
        var members = Enum.GetNames<MfaProviders>();

        // assert — the set is closed; introducing a new provider is a deliberate contract
        // change that requires updating consumers and this test.
        members.Should().BeEquivalentTo(["Email", "Phone", "Authenticator"]);
    }

    [Theory]
    [InlineData(MfaProviders.Email, "Email")]
    [InlineData(MfaProviders.Phone, "Phone")]
    [InlineData(MfaProviders.Authenticator, "Authenticator")]
    public void MfaProviders_NameMatchesEnumMember(MfaProviders provider, string expectedName)
    {
        // arrange / act / assert — pinned names matter because they go on the wire as
        // serialized strings (configured globally with JsonStringEnumConverter / CamelCase).
        provider.ToString().Should().Be(expectedName);
    }
}
