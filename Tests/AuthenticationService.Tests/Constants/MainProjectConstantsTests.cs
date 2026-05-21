using AuthenticationService.Constants;
using AwesomeAssertions;
using Microsoft.Extensions.Logging;

namespace AuthenticationService.Tests.Constants;

/// <summary>
/// Pins SIEM contracts (EventIds, RevocationReasons), error text, rate-limit policy strings,
/// and other wire constants so renames or numeric drift fail at PR time rather than in production.
/// </summary>
public class MainProjectConstantsTests
{
    [Theory]
    [InlineData(nameof(SecurityEventIds.LoginSucceeded), 1001, 1000, 1999)]
    [InlineData(nameof(SecurityEventIds.LoginFailed), 1002, 1000, 1999)]
    [InlineData(nameof(SecurityEventIds.MfaChallengeIssued), 1003, 1000, 1999)]
    [InlineData(nameof(SecurityEventIds.MfaVerified), 1004, 1000, 1999)]
    [InlineData(nameof(SecurityEventIds.MfaFailed), 1005, 1000, 1999)]
    [InlineData(nameof(SecurityEventIds.FailedLoginLockoutTriggered), 1006, 1000, 1999)]
    [InlineData(nameof(SecurityEventIds.RefreshTokenRotated), 1007, 1000, 1999)]
    [InlineData(nameof(SecurityEventIds.RefreshTokenReuseDetected), 1008, 1000, 1999)]
    [InlineData(nameof(SecurityEventIds.LogoutPerDevice), 1009, 1000, 1999)]
    [InlineData(nameof(SecurityEventIds.LogoutAllDevices), 1010, 1000, 1999)]
    [InlineData(nameof(SecurityEventIds.RegistrationCompleted), 2001, 2000, 2999)]
    [InlineData(nameof(SecurityEventIds.EmailConfirmed), 2002, 2000, 2999)]
    [InlineData(nameof(SecurityEventIds.EmailConfirmationFailed), 2003, 2000, 2999)]
    [InlineData(nameof(SecurityEventIds.PasswordChanged), 3001, 3000, 3999)]
    [InlineData(nameof(SecurityEventIds.PasswordResetRequested), 3002, 3000, 3999)]
    [InlineData(nameof(SecurityEventIds.PasswordResetCompleted), 3003, 3000, 3999)]
    [InlineData(nameof(SecurityEventIds.AccountLockedByUser), 3004, 3000, 3999)]
    [InlineData(nameof(SecurityEventIds.MfaEnabled), 3005, 3000, 3999)]
    [InlineData(nameof(SecurityEventIds.ProfileUpdated), 3006, 3000, 3999)]
    [InlineData(nameof(SecurityEventIds.TokenRevoked), 4001, 4000, 4999)]
    [InlineData(nameof(SecurityEventIds.RevokedTokenReplayAttempt), 4002, 4000, 4999)]
    [InlineData(nameof(SecurityEventIds.OrphanedTokenRevoked), 4003, 4000, 4999)]
    [InlineData(nameof(SecurityEventIds.RevokedTokenReplayThresholdWarned), 4004, 4000, 4999)]
    [InlineData(nameof(SecurityEventIds.RevokedTokenReplayThresholdLocked), 4005, 4000, 4999)]
    public void SecurityEventIds_PinExpectedNumericIds(string fieldName, int expectedId, int rangeMin, int rangeMax)
    {
        var field = typeof(SecurityEventIds).GetField(fieldName);
        field.Should().NotBeNull(because: "every public EventId must remain accessible by name.");
        var eventId = (EventId)field!.GetValue(null)!;

        eventId.Id.Should().Be(expectedId);
        eventId.Name.Should().Be(fieldName, because: "Name uses nameof() — rename of the field must update the wire string too.");
        eventId.Id.Should().BeInRange(rangeMin, rangeMax,
            because: "the range buckets (1000s/2000s/3000s/4000s) are part of the SIEM contract.");
    }

    [Fact]
    public void RevocationReasons_PinExpectedWireValues()
    {
        RevocationReasons.Logout.Should().Be("logout");
        RevocationReasons.LogoutAll.Should().Be("logout_all");
        RevocationReasons.PasswordChange.Should().Be("password_change");
        RevocationReasons.PasswordReset.Should().Be("password_reset");
        RevocationReasons.AccountLock.Should().Be("account_lock");
        RevocationReasons.FailedLoginLockout.Should().Be("failed_login_lockout");
        RevocationReasons.ReuseDetected.Should().Be("reuse_detected");
        RevocationReasons.UserNotFound.Should().Be("user_not_found");
    }

    [Fact]
    public void RateLimitPolicies_PinExpectedRegistrationKeys()
    {
        // The string is what [EnableRateLimiting(...)] looks up — rename here without coordinated controller updates
        // silently drops the per-endpoint rate limit.
        RateLimitPolicies.AuthStrict.Should().Be("auth-strict");
        RateLimitPolicies.AuthSensitive.Should().Be("auth-sensitive");
    }

    [Fact]
    public void TokenPurposes_LockoutPinned()
    {
        // Identity's IUserTokenStore separates tokens by (provider, purpose) — rename invalidates
        // every previously-issued panic-button-lock token.
        TokenPurposes.Lockout.Should().Be("Lockout");
    }

    [Fact]
    public void ApiRoutes_ConfirmEmailPinned()
    {
        // Email-confirmation link sits in mailboxes for hours/days — route changes make existing links 404.
        ApiRoutes.ConfirmEmail.Should().Be("/confirm/email");
    }

    [Fact]
    public void WellKnownPaths_PrefixAndDocumentNamesFollowSpec()
    {
        // Standard /.well-known/ URIs from RFC 8615 + OIDC Discovery.
        WellKnownPaths.Prefix.Should().Be(".well-known");
        WellKnownPaths.Jwks.Should().Be("jwks.json");
        WellKnownPaths.OpenIdConfiguration.Should().Be("openid-configuration");
    }

    [Fact]
    public void ErrorMessages_AreNonEmptyAndUniqueAcrossPublicConsts()
    {
        var fields = typeof(ErrorMessages)
            .GetFields(System.Reflection.BindingFlags.Public | System.Reflection.BindingFlags.Static)
            .Where(f => f.IsLiteral && f.FieldType == typeof(string))
            .ToList();

        fields.Should().NotBeEmpty();

        var values = fields.Select(f => (string)f.GetRawConstantValue()!).ToList();

        values.Should().AllSatisfy(v => v.Should().NotBeNullOrWhiteSpace());
        values.Should().OnlyHaveUniqueItems();
    }

    [Theory]
    [InlineData(nameof(ErrorMessages.InvalidRequest), "Invalid request.")]
    [InlineData(nameof(ErrorMessages.InvalidToken), "Token is invalid.")]
    [InlineData(nameof(ErrorMessages.InvalidRefreshToken), "Refresh token is invalid.")]
    [InlineData(nameof(ErrorMessages.ExpiredRefreshToken), "Refresh token has expired.")]
    [InlineData(nameof(ErrorMessages.AccountLocked), "Your account is locked.")]
    [InlineData(nameof(ErrorMessages.AccountLockedFailedAttempts), "Your account is locked due to too many failed login attempts.")]
    [InlineData(nameof(ErrorMessages.InvalidMfaProvider), "Invalid MFA Provider.")]
    [InlineData(nameof(ErrorMessages.PhoneMfaNotConfigured), "Phone MFA is not configured on this deployment.")]
    [InlineData(nameof(ErrorMessages.PhoneNumberNotConfirmed), "Phone number is missing or not confirmed.")]
    [InlineData(nameof(ErrorMessages.InvalidEmailConfirmationRequest), "Invalid email confirmation request")]
    [InlineData(nameof(ErrorMessages.MissingJtiClaim), "Token does not contain a jti claim.")]
    public void ErrorMessages_PinPublishedText(string fieldName, string expected)
    {
        var field = typeof(ErrorMessages).GetField(fieldName);

        var value = (string)field!.GetRawConstantValue()!;

        value.Should().Be(expected);
    }

    [Fact]
    public void UriConstants_AreNonEmpty()
    {
        var fields = typeof(UriConstants)
            .GetFields(System.Reflection.BindingFlags.Public | System.Reflection.BindingFlags.Static)
            .Where(f => f.IsLiteral && f.FieldType == typeof(string))
            .ToList();

        fields.Should().NotBeEmpty();
        fields.Select(f => (string)f.GetRawConstantValue()!)
            .Should().AllSatisfy(v => v.Should().NotBeNullOrWhiteSpace());
    }

    [Fact]
    public void EmailSubjects_AreNonEmptyAndUnique()
    {
        var fields = typeof(EmailSubjects)
            .GetFields(System.Reflection.BindingFlags.Public | System.Reflection.BindingFlags.Static)
            .Where(f => f.IsLiteral && f.FieldType == typeof(string))
            .Select(f => (string)f.GetRawConstantValue()!)
            .ToList();

        fields.Should().NotBeEmpty();
        fields.Should().OnlyHaveUniqueItems();
        fields.Should().AllSatisfy(v => v.Should().NotBeNullOrWhiteSpace());
    }

    [Fact]
    public void UserConstants_AdminUsernamePinned()
    {
        // Operators look for "admin" specifically when troubleshooting — renaming breaks runbooks.
        UserConstants.Admin.Should().Be("admin");
    }

    [Fact]
    public void RouteConstants_PageRoutes_ArePinnedWithLeadingSlash()
    {
        // Leading slash is the Razor convention; absent it the redirect resolves relative to current page.
        PageRouteConstants.ResetPassword.Should().Be("/ResetPassword");
        PageRouteConstants.LockAccount.Should().Be("/LockAccount");
        PageRouteConstants.ActionComplete.Should().Be("/ActionComplete");

        new[] {
            PageRouteConstants.ResetPassword,
            PageRouteConstants.LockAccount,
            PageRouteConstants.ActionComplete
        }.Should().AllSatisfy(r => r.Should().StartWith("/"));
    }

    [Fact]
    public void ResponseConstants_BadRequestAndUnauthorizedKeys_Pinned()
    {
        // Clients deserialize the Errors dictionary and look up by these exact keys.
        ResponseConstants.BadRequest.Should().Be("Bad Request");
        ResponseConstants.Unauthorized.Should().Be("Unauthorized");
    }

    [Fact]
    public void RevocationReasons_AllValues_AreUniqueAndSnakeCase()
    {
        var values = typeof(RevocationReasons)
            .GetFields(System.Reflection.BindingFlags.Public | System.Reflection.BindingFlags.Static)
            .Where(f => f.IsLiteral && f.FieldType == typeof(string))
            .Select(f => (string)f.GetRawConstantValue()!)
            .ToList();

        values.Should().NotBeEmpty();
        values.Should().OnlyHaveUniqueItems();
        values.Should().AllSatisfy(v => v.Should().MatchRegex("^[a-z_]+$"));
    }
}
