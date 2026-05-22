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
        // arrange — Email is the default value of the MfaProviders enum (declaration order); change-of-default would
        // silently shift which channel new users get prompted on.
        var user = new User();

        // assert
        user.PreferredMfaProvider.Should().Be(Shared.Enums.MfaProviders.Email);
    }

    [Fact]
    public void RevokedToken_TokenJtiRequired()
    {
        // arrange
        var entity = new RevokedToken { TokenJti = null!, UserId = "u" };

        // act
        var results = ValidateRecursive(entity);

        // assert
        results.Should().Contain(r => r.MemberNames.Contains(nameof(RevokedToken.TokenJti)));
    }

    [Fact]
    public void RevokedToken_RevokedFromIpAndRevocationReason_RespectMaxLength()
    {
        // arrange
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
        // arrange — must default null; a non-null default would mean every newly-revoked token starts
        // already-escalated and never fires its first warn/lock event.
        var entity = new RevokedToken { TokenJti = "j", UserId = "u" };

        // assert
        entity.WarnedAt.Should().BeNull();
        entity.LockedAt.Should().BeNull();
    }

    [Fact]
    public void RevokedTokenAccessAttempt_Defaults_SeverityNone()
    {
        // arrange
        var attempt = new RevokedTokenAccessAttempt();

        // assert
        attempt.Severity.Should().Be(Severity.None);
    }

    [Fact]
    public void RefreshToken_DefaultInstance_TimestampsDefaulted()
    {
        // arrange
        var entity = new RefreshToken();

        // assert
        entity.CreatedAt.Should().Be(default);
        entity.ExpiresAt.Should().Be(default);
        entity.ConsumedAt.Should().BeNull();
        entity.RevocationReason.Should().BeNull();
        entity.ReplacedByTokenId.Should().BeNull();
    }

    [Fact]
    public void Role_PropertyShape_ExposesDescription()
    {
        // arrange
        var role = new Role { Description = "Default user role" };

        // assert
        role.Description.Should().Be("Default user role");
    }

    private static List<ValidationResult> ValidateRecursive(object instance)
    {
        var results = new List<ValidationResult>();
        Validator.TryValidateObject(instance, new ValidationContext(instance), results, validateAllProperties: true);
        return results;
    }
}
