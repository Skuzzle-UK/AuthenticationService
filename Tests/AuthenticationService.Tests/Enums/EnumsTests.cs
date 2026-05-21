using AuthenticationService.Enums;
using AwesomeAssertions;

namespace AuthenticationService.Tests.Enums;

/// <summary>
/// Pins internal enum names and ordering — their string representations form a SIEM contract,
/// so reordering or renaming would silently shift downstream alerting.
/// </summary>
public class EnumsTests
{
    [Fact]
    public void Severity_DeclaresExpectedMembersAndOrder()
    {
        // Explicit values because Severity comparisons depend on numeric ordering.
        ((int)Severity.None).Should().Be(0);
        ((int)Severity.Low).Should().Be(1);
        ((int)Severity.Medium).Should().Be(2);
        ((int)Severity.High).Should().Be(3);

        Enum.GetNames<Severity>().Should().BeEquivalentTo(["None", "Low", "Medium", "High"]);
    }

    [Fact]
    public void LoginFailureReason_DeclaresExpectedMembers()
    {
        // Names go on the wire as the {Reason} field of the LoginFailed SIEM event.
        Enum.GetNames<LoginFailureReason>()
            .Should().BeEquivalentTo(["BadCredentials", "AccountLocked", "EmailNotConfirmed"]);
    }

    [Theory]
    [InlineData(LoginFailureReason.BadCredentials, "BadCredentials")]
    [InlineData(LoginFailureReason.AccountLocked, "AccountLocked")]
    [InlineData(LoginFailureReason.EmailNotConfirmed, "EmailNotConfirmed")]
    public void LoginFailureReason_NameMatchesEnumMember(LoginFailureReason reason, string expected)
    {
        reason.ToString().Should().Be(expected);
    }
}
