using AuthenticationService.Shared.Enums;
using AwesomeAssertions;

namespace AuthenticationService.Shared.Tests.Enums;

/// <summary>
/// MfaProviders is a wire enum (serialised into JSON responses + request bodies via
/// JsonStringEnumConverter). Pins names + member set so reordering or renaming is caught.
/// </summary>
public class MfaProvidersTests
{
    [Fact]
    public void MfaProviders_DeclaresExpectedMembers_AndOnlyThose()
    {
        var members = Enum.GetNames<MfaProviders>();

        // Closed set — adding a provider is a deliberate contract change.
        members.Should().BeEquivalentTo(["Email", "Phone", "Authenticator"]);
    }

    [Theory]
    [InlineData(MfaProviders.Email, "Email")]
    [InlineData(MfaProviders.Phone, "Phone")]
    [InlineData(MfaProviders.Authenticator, "Authenticator")]
    public void MfaProviders_NameMatchesEnumMember(MfaProviders provider, string expectedName)
    {
        provider.ToString().Should().Be(expectedName);
    }
}
