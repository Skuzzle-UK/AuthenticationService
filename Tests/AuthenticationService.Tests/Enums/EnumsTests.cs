using AuthenticationService.Enums;
using AwesomeAssertions;

namespace AuthenticationService.Tests.Enums;

/// <summary>
/// <para>Internal enums (<see cref="Severity"/>, <see cref="LoginFailureReason"/>) are
/// emitted into log messages — Severity in the threshold-escalation worker, LoginFailureReason
/// as a SIEM payload field. Their string representations form a SIEM contract; reordering
/// or renaming would silently shift downstream alerting.</para>
/// </summary>
public class EnumsTests
{
    [Fact]
    public void Severity_DeclaresExpectedMembersAndOrder()
    {
        // arrange / act — explicitly assigned values 0..3 because Severity comparisons
        // (e.g., "is this above Medium?") depend on numeric ordering.
        ((int)Severity.None).Should().Be(0);
        ((int)Severity.Low).Should().Be(1);
        ((int)Severity.Medium).Should().Be(2);
        ((int)Severity.High).Should().Be(3);

        // assert — the closed set, no accidental new members.
        Enum.GetNames<Severity>().Should().BeEquivalentTo(["None", "Low", "Medium", "High"]);
    }

    [Fact]
    public void LoginFailureReason_DeclaresExpectedMembers()
    {
        // arrange / act / assert — names go on the wire as part of the {Reason} field of
        // the LoginFailed SIEM event. Reordering or renaming silently changes payloads
        // every SIEM rule sees.
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
