using System.ComponentModel.DataAnnotations;
using AuthenticationService.Entities;
using AuthenticationService.Enums;
using AwesomeAssertions;

namespace AuthenticationService.Tests.Entities;

/// <summary>
/// Pins column-shape invariants on EF Core entities so a model change that drops a
/// Required without a corresponding migration is caught at PR time.
/// </summary>
public class EntitiesTests
{
    [Fact]
    public void User_DefaultInstance_PreferredMfaProviderIsEmail()
    {
        // Email is the default value of the MfaProviders enum (declaration order); change-of-default would
        // silently shift which channel new users get prompted on.
        var user = new User();

        user.PreferredMfaProvider.Should().Be(Shared.Enums.MfaProviders.Email);
    }

    [Fact]
    public void RevokedToken_TokenJtiRequired()
    {
        var entity = new RevokedToken { TokenJti = null!, UserId = "u" };

        var results = ValidateRecursive(entity);

        results.Should().Contain(r => r.MemberNames.Contains(nameof(RevokedToken.TokenJti)));
    }

    [Fact]
    public void RevokedToken_RevokedFromIpAndRevocationReason_RespectMaxLength()
    {
        var entity = new RevokedToken
        {
            TokenJti = "jti",
            UserId = "u",
            RevokedFromIp = new string('1', 46),
            RevocationReason = new string('r', 51),
        };

        var results = ValidateRecursive(entity);

        results.Should().Contain(r => r.MemberNames.Contains(nameof(RevokedToken.RevokedFromIp)));
        results.Should().Contain(r => r.MemberNames.Contains(nameof(RevokedToken.RevocationReason)));
    }

    [Fact]
    public void RevokedToken_WarnedAtAndLockedAt_DefaultNullSoEscalationStartsFresh()
    {
        // Must default null — a non-null default would mean every newly-revoked token starts
        // already-escalated and never fires its first warn/lock event.
        var entity = new RevokedToken { TokenJti = "j", UserId = "u" };

        entity.WarnedAt.Should().BeNull();
        entity.LockedAt.Should().BeNull();
    }

    [Fact]
    public void RevokedTokenAccessAttempt_Defaults_SeverityNone()
    {
        var attempt = new RevokedTokenAccessAttempt();

        attempt.Severity.Should().Be(Severity.None);
    }

    [Fact]
    public void RefreshToken_DefaultInstance_TimestampsDefaulted()
    {
        var entity = new RefreshToken();

        entity.CreatedAt.Should().Be(default);
        entity.ExpiresAt.Should().Be(default);
        entity.ConsumedAt.Should().BeNull();
        entity.RevocationReason.Should().BeNull();
        entity.ReplacedByTokenId.Should().BeNull();
    }

    [Fact]
    public void Role_PropertyShape_ExposesDescription()
    {
        var role = new Role { Description = "Default user role" };

        role.Description.Should().Be("Default user role");
    }

    private static List<ValidationResult> ValidateRecursive(object instance)
    {
        var results = new List<ValidationResult>();
        Validator.TryValidateObject(instance, new ValidationContext(instance), results, validateAllProperties: true);
        return results;
    }
}
