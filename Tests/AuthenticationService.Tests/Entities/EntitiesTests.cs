using System.ComponentModel.DataAnnotations;
using AuthenticationService.Entities;
using AuthenticationService.Enums;
using AwesomeAssertions;

namespace AuthenticationService.Tests.Entities;

/// <summary>
/// <para>EF Core entities are mostly data-shape — properties map to columns, attributes
/// (Required / MaxLength) reflect column constraints. The tests pin the column-shape
/// invariants so a model change that drops a Required without a corresponding migration
/// is caught at PR time.</para>
///
/// <para>Entities covered: <see cref="User"/> (residual fields), <see cref="Role"/>,
/// <see cref="RefreshToken"/>, <see cref="RevokedToken"/>, <see cref="RevokedTokenAccessAttempt"/>.</para>
/// </summary>
public class EntitiesTests
{
    [Fact]
    public void User_DefaultInstance_PreferredMfaProviderIsEmail()
    {
        // arrange / act — Email is the default value of the MfaProviders enum
        // (declaration order). Tests pin this because change-of-default would silently
        // change which channel the system prompts on for new users.
        var user = new User();

        // assert
        user.PreferredMfaProvider.Should().Be(Shared.Enums.MfaProviders.Email);
    }

    [Fact]
    public void RevokedToken_TokenJtiRequired()
    {
        // arrange — TokenJti is the lookup key in the deny-list. A null-jti row would be
        // a corrupt row that breaks middleware lookup.
        var entity = new RevokedToken { TokenJti = null!, UserId = "u" };

        // act
        var results = ValidateRecursive(entity);

        // assert
        results.Should().Contain(r => r.MemberNames.Contains(nameof(RevokedToken.TokenJti)));
    }

    [Fact]
    public void RevokedToken_RevokedFromIpAndRevocationReason_RespectMaxLength()
    {
        // arrange — IPv6 max length is 45 characters; revocation reason values from
        // RevocationReasons are short snake_case strings (50 char cap is comfortable).
        var entity = new RevokedToken
        {
            TokenJti = "jti",
            UserId = "u",
            RevokedFromIp = new string('1', 46),
            RevocationReason = new string('r', 51),
        };

        // act
        var results = ValidateRecursive(entity);

        // assert
        results.Should().Contain(r => r.MemberNames.Contains(nameof(RevokedToken.RevokedFromIp)));
        results.Should().Contain(r => r.MemberNames.Contains(nameof(RevokedToken.RevocationReason)));
    }

    [Fact]
    public void RevokedToken_WarnedAtAndLockedAt_DefaultNullSoEscalationStartsFresh()
    {
        // arrange / act — the threshold-escalation worker uses these timestamps to track
        // "have we already fired a warn / lock on this token?". They MUST default null —
        // a non-null default would mean every newly-revoked token starts in the
        // already-escalated state and never fires its first warn/lock event.
        var entity = new RevokedToken { TokenJti = "j", UserId = "u" };

        // assert
        entity.WarnedAt.Should().BeNull();
        entity.LockedAt.Should().BeNull();
    }

    [Fact]
    public void RevokedTokenAccessAttempt_Defaults_SeverityNone()
    {
        // arrange / act — the recorded severity defaults to None, with the
        // RecordRevokedReplayAsync caller responsible for filling in Low / Medium based on
        // whether the token was still-live or naturally-expired at replay time.
        var attempt = new RevokedTokenAccessAttempt();

        // assert
        attempt.Severity.Should().Be(Severity.None);
    }

    [Fact]
    public void RefreshToken_DefaultInstance_TimestampsDefaulted()
    {
        // arrange / act
        var entity = new RefreshToken();

        // assert — default(DateTime) is MinValue. Real rows are populated by JWTService
        // before insert; tests document that nothing else is auto-populated.
        entity.CreatedAt.Should().Be(default);
        entity.ExpiresAt.Should().Be(default);
        entity.ConsumedAt.Should().BeNull();
        entity.RevocationReason.Should().BeNull();
        entity.ReplacedByTokenId.Should().BeNull();
    }

    [Fact]
    public void Role_PropertyShape_ExposesDescription()
    {
        // arrange / act
        var role = new Role { Description = "Default user role" };

        // assert — Role inherits IdentityRole and adds Description; pin the property
        // exists and is mutable so a refactor that drops it doesn't slip through.
        role.Description.Should().Be("Default user role");
    }

    private static List<ValidationResult> ValidateRecursive(object instance)
    {
        var results = new List<ValidationResult>();
        Validator.TryValidateObject(instance, new ValidationContext(instance), results, validateAllProperties: true);
        return results;
    }
}
