using System.Security.Claims;
using AuthenticationService.Shared.Constants;
using AuthenticationService.Shared.Extensions;
using AwesomeAssertions;

namespace AuthenticationService.Shared.Tests.Extensions;

/// <summary>
/// Validates the convenience reads on <see cref="ClaimsPrincipal"/>. These extensions
/// replace seven near-identical inline reads of the <c>sub</c> claim across the
/// controller layer.
/// </summary>
public class ClaimsPrincipalExtensionsTests
{
    [Fact]
    public void GetUserId_ReadsSubClaim()
    {
        // arrange
        var principal = BuildPrincipal((ClaimConstants.Sub, "u-42"));

        // act + assert
        principal.GetUserId().Should().Be("u-42");
    }

    [Fact]
    public void GetUserId_MissingClaim_ReturnsNull()
    {
        // arrange — unauthenticated principal with no claims.
        var principal = new ClaimsPrincipal(new ClaimsIdentity());

        // act + assert
        principal.GetUserId().Should().BeNull(
            because: "callers that need a non-null fallback should coalesce themselves — the extension stays faithful to FindFirst's null shape");
    }

    [Fact]
    public void GetTenantId_ReadsTidClaim()
    {
        // arrange
        var principal = BuildPrincipal((ClaimConstants.Tid, "acme"));

        // act + assert
        principal.GetTenantId().Should().Be("acme");
    }

    [Fact]
    public void GetTenantId_MissingClaim_ReturnsNull()
    {
        // arrange — platform-admin tokens act platform-wide and don't carry tid.
        var principal = BuildPrincipal((ClaimConstants.Sub, "u-1"));

        // act + assert
        principal.GetTenantId().Should().BeNull();
    }

    [Fact]
    public void GetUserIdOrEmpty_PresentClaim_ReturnsValue()
    {
        // arrange
        var principal = BuildPrincipal((ClaimConstants.Sub, "u-42"));

        // act + assert
        principal.GetUserIdOrEmpty().Should().Be("u-42");
    }

    [Fact]
    public void GetUserIdOrEmpty_MissingClaim_ReturnsEmpty()
    {
        // arrange — used by audit-log enrichment paths that need non-null strings.
        var principal = new ClaimsPrincipal(new ClaimsIdentity());

        // act + assert
        principal.GetUserIdOrEmpty().Should().BeEmpty(
            because: "in production this case can't be reached past [Authorize], but the safety net is the point");
    }

    [Fact]
    public void GetRoles_NoRoleClaims_ReturnsEmpty()
    {
        // arrange
        var principal = BuildPrincipal((ClaimConstants.Sub, "u-1"));

        // act + assert — never null; complements IsInRole's single-role question.
        principal.GetRoles().Should().BeEmpty();
    }

    [Fact]
    public void GetRoles_MultipleRoleClaims_ReturnsAllValues()
    {
        // arrange — JWT array claims arrive as multiple Claim instances all of type "role".
        var principal = BuildPrincipal(
            (ClaimConstants.Sub, "u-1"),
            (ClaimConstants.Role, "Admin"),
            (ClaimConstants.Role, "PlatformAdmin"),
            (ClaimConstants.Role, "DefaultUser"));

        // act + assert
        principal.GetRoles().Should().BeEquivalentTo([
            RolesConstants.Admin,
            RolesConstants.PlatformAdmin,
            RolesConstants.DefaultUser
        ]);
    }

    [Fact]
    public void GetRoles_DoesNotPickUpOtherClaimTypes()
    {
        // arrange — defensive check that the extension reads ClaimConstants.Role only.
        // {name} is also a string-valued claim; it must not leak into the role set.
        var principal = BuildPrincipal(
            (ClaimConstants.Role, "Admin"),
            (ClaimConstants.Name, "alice"));

        // act + assert
        principal.GetRoles().Should().ContainSingle().Which.Should().Be("Admin");
    }

    [Fact]
    public void GetUserId_DoesNotMatchOtherClaimTypes()
    {
        // arrange — defensive check that the extension reads sub, not any string-typed
        // claim that happens to live nearby (e.g. name, jti).
        var principal = BuildPrincipal(
            (ClaimConstants.Name, "alice"),
            (ClaimConstants.Jti, "token-id"));

        // act + assert
        principal.GetUserId().Should().BeNull();
    }

    private static ClaimsPrincipal BuildPrincipal(params (string Type, string Value)[] claims)
    {
        var identity = new ClaimsIdentity(
            claims.Select(c => new Claim(c.Type, c.Value)),
            authenticationType: "test");
        return new ClaimsPrincipal(identity);
    }
}
