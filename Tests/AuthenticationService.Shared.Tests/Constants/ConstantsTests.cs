using AuthenticationService.Shared.Constants;
using AwesomeAssertions;

namespace AuthenticationService.Shared.Tests.Constants;

/// <summary>
/// <para>Constants in the shared package form a wire contract — values are read directly
/// by JwtBearer's <c>TokenValidationParameters</c> in consuming services. Changing any of
/// these silently breaks every consumer that doesn't redeploy at the same time. These
/// tests pin the strings so an accidental rename is caught at PR time, and so policy /
/// role lookups don't drift between issuer and consumer.</para>
/// </summary>
public class ConstantsTests
{
    /// <summary>
    /// Standard JWT/OIDC claim names — must match RFC 7519 / OIDC Core. Changing any of these
    /// breaks JwtBearer validation, refresh-token-family lookup (sid), and all UserId reads.
    /// </summary>
    [Fact]
    public void ClaimConstants_PinExpectedWireValues()
    {
        ClaimConstants.Sub.Should().Be("sub");
        ClaimConstants.Sid.Should().Be("sid");
        ClaimConstants.Jti.Should().Be("jti");
        ClaimConstants.Exp.Should().Be("exp");
        ClaimConstants.Name.Should().Be("name");
        ClaimConstants.Email.Should().Be("email");
        ClaimConstants.Role.Should().Be("role");
    }

    /// <summary>
    /// Authorisation policies are referenced by string from <c>[Authorize(Policy=...)]</c>
    /// attributes; renaming silently makes the policy "not registered" → endpoint becomes
    /// open to any authenticated caller. Pinned here.
    /// </summary>
    [Fact]
    public void PolicyConstants_AdminOnlyValuePinned()
    {
        PolicyConstants.AdminOnly.Should().Be("AdminOnly");
    }

    [Fact]
    public void RolesConstants_DisplayNames_PinExpectedWireValues()
    {
        // Role names get serialized into JWTs and read by every consumer. Renaming would
        // either crash existing tokens (claim-mismatch) or — worse — silently grant the
        // wrong role.
        RolesConstants.Admin.Should().Be("Admin");
        RolesConstants.DefaultUser.Should().Be("DefaultUser");
    }

    [Fact]
    public void RolesConstants_NormalisedNames_AreUppercaseFormsForIdentityDirectSeed()
    {
        // ASP.NET Core Identity stores roles in two columns: display name + a normalised
        // (upper-case) form used for indexed lookups. When we seed roles directly via EF
        // (rather than via RoleManager which would do the normalisation for us) we use
        // these. They MUST be exact upper-case versions of the display names — Identity's
        // lookup will silently miss otherwise.
        RolesConstants.Normalised.Admin.Should().Be(RolesConstants.Admin.ToUpperInvariant());
        RolesConstants.Normalised.DefaultUser.Should().Be(RolesConstants.DefaultUser.ToUpperInvariant());
    }

    [Fact]
    public void AuthSchemeConstants_BearerAndBearerPrefix_MatchHeaderConvention()
    {
        // The Bearer prefix is what the Authorization header carries — "Bearer <jwt>".
        // Code that strips this prefix from the header to recover the raw JWT must pin
        // the exact spelling and trailing space, or the service rejects every legitimate
        // request as malformed.
        AuthSchemeConstants.Bearer.Should().Be("Bearer");
        AuthSchemeConstants.BearerPrefix.Should().Be("Bearer ");
        AuthSchemeConstants.BearerPrefix.Should().StartWith(AuthSchemeConstants.Bearer);
        AuthSchemeConstants.BearerPrefix.Should().EndWith(" ");
    }
}
