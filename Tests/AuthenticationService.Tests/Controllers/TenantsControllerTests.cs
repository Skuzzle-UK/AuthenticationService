using System.Security.Claims;
using AuthenticationService.Controllers;
using AuthenticationService.Services;
using AuthenticationService.Shared.Constants;
using AuthenticationService.Shared.Dtos;
using AuthenticationService.Shared.Dtos.Response;
using AwesomeAssertions;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using NSubstitute;

namespace AuthenticationService.Tests.Controllers;

/// <summary>
/// Controller-layer tests for <see cref="TenantsController"/>. Service results map to the
/// expected HTTP status codes (200 / 201 / 204 / 400 / 404 / 409). The authorization gate
/// itself isn't tested here — the controller is decorated with
/// <c>[Authorize(Policy = PolicyConstants.PlatformAdminOnly)]</c>; policy resolution is
/// tested at the integration layer.
/// </summary>
public class TenantsControllerTests
{
    private const string PlatformAdminId = "platform-admin-1";

    [Fact]
    public async Task ListTenantsAsync_ReturnsOkWithServiceList()
    {
        // arrange
        var (controller, tenantService) = BuildController();
        var summary = new TenantSummaryDto
        {
            Id = "t-1",
            Name = "acme",
            DisplayName = "Acme",
            Status = "Active",
            CreatedAt = DateTimeOffset.UtcNow,
        };
        tenantService.ListAsync(Arg.Any<CancellationToken>())
            .Returns(new List<TenantSummaryDto> { summary });

        // act
        var result = await controller.ListTenantsAsync(CancellationToken.None);

        // assert
        var ok = result.Should().BeOfType<OkObjectResult>().Subject;
        var body = ok.Value.Should().BeAssignableTo<IEnumerable<TenantSummaryDto>>().Subject;
        body.Should().ContainSingle().Which.Name.Should().Be("acme");
    }

    [Fact]
    public async Task GetTenantAsync_KnownName_ReturnsOk()
    {
        // arrange
        var (controller, tenantService) = BuildController();
        var detail = new TenantDetailDto { Name = "acme", DisplayName = "Acme", Status = "Active" };
        tenantService.GetByNameAsync("acme", Arg.Any<CancellationToken>()).Returns(detail);

        // act
        var result = await controller.GetTenantAsync("acme", CancellationToken.None);

        // assert
        result.Should().BeOfType<OkObjectResult>()
              .Which.Value.Should().BeSameAs(detail);
    }

    [Fact]
    public async Task GetTenantAsync_UnknownName_Returns404()
    {
        // arrange
        var (controller, tenantService) = BuildController();
        tenantService.GetByNameAsync("missing", Arg.Any<CancellationToken>())
            .Returns((TenantDetailDto?)null);

        // act
        var result = await controller.GetTenantAsync("missing", CancellationToken.None);

        // assert
        result.Should().BeOfType<NotFoundResult>();
    }

    [Fact]
    public async Task CreateTenantAsync_Success_Returns201()
    {
        // arrange
        var (controller, tenantService) = BuildController();
        tenantService.CreateAsync("acme", "Acme", PlatformAdminId, Arg.Any<CancellationToken>())
            .Returns(new CreateTenantResult.Success("t-1", "acme"));

        // act
        var result = await controller.CreateTenantAsync(
            new CreateTenantDto { Name = "acme", DisplayName = "Acme" }, CancellationToken.None);

        // assert
        result.Should().BeOfType<CreatedAtActionResult>();
    }

    [Fact]
    public async Task CreateTenantAsync_InvalidName_Returns400()
    {
        // arrange
        var (controller, tenantService) = BuildController();
        tenantService.CreateAsync(Arg.Any<string>(), Arg.Any<string>(), Arg.Any<string>(), Arg.Any<CancellationToken>())
            .Returns(new CreateTenantResult.InvalidName("Name is reserved."));

        // act
        var result = await controller.CreateTenantAsync(
            new CreateTenantDto { Name = "admin", DisplayName = "Bad" }, CancellationToken.None);

        // assert — ValidationProblem returns 400 by default with ProblemDetails payload.
        var bad = result.Should().BeAssignableTo<ObjectResult>().Subject;
        bad.StatusCode.Should().Be(400);
    }

    [Fact]
    public async Task CreateTenantAsync_DuplicateName_Returns409()
    {
        // arrange
        var (controller, tenantService) = BuildController();
        tenantService.CreateAsync(Arg.Any<string>(), Arg.Any<string>(), Arg.Any<string>(), Arg.Any<CancellationToken>())
            .Returns(new CreateTenantResult.NameAlreadyExists());

        // act
        var result = await controller.CreateTenantAsync(
            new CreateTenantDto { Name = "acme", DisplayName = "Dup" }, CancellationToken.None);

        // assert
        result.Should().BeOfType<ConflictObjectResult>();
    }

    [Fact]
    public async Task SuspendTenantAsync_Success_Returns204()
    {
        // arrange
        var (controller, tenantService) = BuildController();
        tenantService.SuspendAsync("acme", "reason", PlatformAdminId, Arg.Any<CancellationToken>())
            .Returns(new TenantLifecycleResult.Success());

        // act
        var result = await controller.SuspendTenantAsync(
            "acme", new SuspendTenantDto { Reason = "reason" }, CancellationToken.None);

        // assert
        result.Should().BeOfType<NoContentResult>();
    }

    [Fact]
    public async Task SuspendTenantAsync_NotFound_Returns404()
    {
        // arrange
        var (controller, tenantService) = BuildController();
        tenantService.SuspendAsync(Arg.Any<string>(), Arg.Any<string>(), Arg.Any<string>(), Arg.Any<CancellationToken>())
            .Returns(new TenantLifecycleResult.NotFound());

        // act
        var result = await controller.SuspendTenantAsync(
            "missing", new SuspendTenantDto { Reason = "x" }, CancellationToken.None);

        // assert
        result.Should().BeOfType<NotFoundResult>();
    }

    [Fact]
    public async Task SuspendTenantAsync_AlreadySuspended_Returns409()
    {
        // arrange
        var (controller, tenantService) = BuildController();
        tenantService.SuspendAsync(Arg.Any<string>(), Arg.Any<string>(), Arg.Any<string>(), Arg.Any<CancellationToken>())
            .Returns(new TenantLifecycleResult.InvalidStateTransition("Suspended"));

        // act
        var result = await controller.SuspendTenantAsync(
            "acme", new SuspendTenantDto { Reason = "x" }, CancellationToken.None);

        // assert
        result.Should().BeOfType<ConflictObjectResult>();
    }

    [Fact]
    public async Task SoftDeleteTenantAsync_Success_Returns204()
    {
        // arrange
        var (controller, tenantService) = BuildController();
        tenantService.SoftDeleteAsync("acme", PlatformAdminId, Arg.Any<CancellationToken>())
            .Returns(new TenantLifecycleResult.Success());

        // act
        var result = await controller.SoftDeleteTenantAsync("acme", CancellationToken.None);

        // assert
        result.Should().BeOfType<NoContentResult>();
    }

    [Fact]
    public async Task ForceDeleteTenantAsync_RightConfirmation_Returns204()
    {
        // arrange
        var (controller, tenantService) = BuildController();
        tenantService.ForceDeleteAsync("acme", "acme", PlatformAdminId, Arg.Any<CancellationToken>())
            .Returns(new TenantLifecycleResult.Success());

        // act
        var result = await controller.ForceDeleteTenantAsync(
            "acme", new ForceDeleteTenantDto { ConfirmName = "acme" }, CancellationToken.None);

        // assert
        result.Should().BeOfType<NoContentResult>();
    }

    [Fact]
    public async Task ForceDeleteTenantAsync_WrongConfirmation_Returns400()
    {
        // arrange
        var (controller, tenantService) = BuildController();
        tenantService.ForceDeleteAsync(Arg.Any<string>(), Arg.Any<string>(), Arg.Any<string>(), Arg.Any<CancellationToken>())
            .Returns(new TenantLifecycleResult.ConfirmationMismatch());

        // act
        var result = await controller.ForceDeleteTenantAsync(
            "acme", new ForceDeleteTenantDto { ConfirmName = "wrong" }, CancellationToken.None);

        // assert
        result.Should().BeOfType<BadRequestObjectResult>();
    }

    private static (TenantsController controller, ITenantService tenantService) BuildController()
    {
        var tenantService = Substitute.For<ITenantService>();
        var controller = new TenantsController(tenantService);

        var claims = new[] { new Claim(ClaimConstants.Sub, PlatformAdminId) };
        controller.ControllerContext = new ControllerContext
        {
            HttpContext = new DefaultHttpContext
            {
                User = new ClaimsPrincipal(new ClaimsIdentity(claims, authenticationType: "test")),
            },
        };

        return (controller, tenantService);
    }
}
