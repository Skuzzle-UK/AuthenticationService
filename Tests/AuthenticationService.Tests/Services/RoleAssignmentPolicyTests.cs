using AuthenticationService.Services;
using AuthenticationService.Shared.Constants;
using AwesomeAssertions;

namespace AuthenticationService.Tests.Services;

/// <summary>
/// Validates the allow-list shape of <see cref="RoleAssignmentPolicy"/> (multi-tenancy
/// Decision 5). The rules: Admin is seed-only (never assignable); PlatformAdmin requires
/// the caller to hold PlatformAdmin; everything else is open to either Admin or
/// PlatformAdmin holders.
/// </summary>
public class RoleAssignmentPolicyTests
{
    private readonly RoleAssignmentPolicy _policy = new();

    [Fact]
    public void AdminRole_IsSeedOnly_ForbiddenForEveryCaller()
    {
        // arrange — even a caller holding both Admin and PlatformAdmin can't grant Admin
        // through this surface. The Admin role is a legacy pre-multi-tenancy concept and
        // only the DB seed creates it.
        var callerRoles = new[] { RolesConstants.Admin, RolesConstants.PlatformAdmin };

        // act
        var forbidden = _policy.Forbidden(callerRoles, [RolesConstants.Admin]);

        // assert
        forbidden.Should().ContainSingle().Which.Should().Be(RolesConstants.Admin);
    }

    [Fact]
    public void PlatformAdmin_BlockedWhenCallerLacksIt()
    {
        // arrange — Admin without PlatformAdmin is the privilege-escalation scenario.
        var callerRoles = new[] { RolesConstants.Admin };

        // act
        var forbidden = _policy.Forbidden(callerRoles, [RolesConstants.PlatformAdmin]);

        // assert
        forbidden.Should().ContainSingle().Which.Should().Be(
            RolesConstants.PlatformAdmin,
            because: "an Admin without PlatformAdmin cannot grant PlatformAdmin to anyone — that's the escalation path we're blocking");
    }

    [Fact]
    public void PlatformAdmin_AllowedWhenCallerHoldsIt()
    {
        // arrange
        var callerRoles = new[] { RolesConstants.PlatformAdmin };

        // act
        var forbidden = _policy.Forbidden(callerRoles, [RolesConstants.PlatformAdmin]);

        // assert
        forbidden.Should().BeEmpty(
            because: "an existing PlatformAdmin is the legitimate grantor of more PlatformAdmins");
    }

    [Fact]
    public void NonElevatedRole_AllowedForAdminCaller()
    {
        // arrange
        var callerRoles = new[] { RolesConstants.Admin };

        // act
        var forbidden = _policy.Forbidden(callerRoles, [RolesConstants.DefaultUser]);

        // assert
        forbidden.Should().BeEmpty();
    }

    [Fact]
    public void NonElevatedRole_AllowedForPlatformAdminCaller()
    {
        // arrange — a PlatformAdmin without Admin still represents enough authority to
        // grant non-elevated roles. (The current AdminController is gated to Admin so
        // this state isn't reachable through that endpoint today; the policy answer is
        // still defined so future endpoints can flow through it.)
        var callerRoles = new[] { RolesConstants.PlatformAdmin };

        // act
        var forbidden = _policy.Forbidden(callerRoles, [RolesConstants.DefaultUser]);

        // assert
        forbidden.Should().BeEmpty();
    }

    [Fact]
    public void NonElevatedRole_BlockedForCallerWithNeitherRole()
    {
        // arrange — defence-in-depth check. If a future endpoint forgets the [Authorize]
        // attribute, the policy still refuses.
        var callerRoles = Array.Empty<string>();

        // act
        var forbidden = _policy.Forbidden(callerRoles, [RolesConstants.DefaultUser]);

        // assert
        forbidden.Should().ContainSingle().Which.Should().Be(RolesConstants.DefaultUser);
    }

    [Fact]
    public void MixedRequest_ReportsEveryForbiddenRole()
    {
        // arrange — caller holds Admin only. They request DefaultUser (ok), Admin
        // (always forbidden), and PlatformAdmin (forbidden for non-PlatformAdmin caller).
        // The policy should report both forbidden roles in one go so the endpoint can
        // 400 with the full list.
        var callerRoles = new[] { RolesConstants.Admin };
        var requested = new[] { RolesConstants.DefaultUser, RolesConstants.Admin, RolesConstants.PlatformAdmin };

        // act
        var forbidden = _policy.Forbidden(callerRoles, requested);

        // assert
        forbidden.Should().BeEquivalentTo([RolesConstants.Admin, RolesConstants.PlatformAdmin]);
    }

    [Fact]
    public void EmptyTargetRoles_ReturnsEmpty()
    {
        // arrange + act
        var forbidden = _policy.Forbidden([RolesConstants.Admin], Array.Empty<string>());

        // assert
        forbidden.Should().BeEmpty();
    }
}
