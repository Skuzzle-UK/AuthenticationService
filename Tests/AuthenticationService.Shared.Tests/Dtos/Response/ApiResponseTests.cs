using AuthenticationService.Shared.Dtos.Response;
using AwesomeAssertions;

namespace AuthenticationService.Shared.Tests.Dtos.Response;

/// <summary>
/// Covers the success/error envelope's mutation methods (AddError, AddErrors, Successful)
/// — the only way to flip IsSuccessful, called from every controller.
/// </summary>
public class ApiResponseTests
{
    [Fact]
    public void DefaultState_IsSuccessfulWithNoErrors()
    {
        var response = new ApiResponse();

        response.IsSuccessful.Should().BeTrue();
        response.Errors.Should().BeNull();
    }

    [Fact]
    public void AddError_FirstCall_AllocatesDictionaryAndFlipsToUnsuccessful()
    {
        var response = new ApiResponse();

        var returned = response.AddError("key1", "error1");

        returned.Should().BeSameAs(response, because: "fluent chaining contract");
        response.IsSuccessful.Should().BeFalse();
        response.Errors.Should().NotBeNull().And.ContainKey("key1");
        response.Errors!["key1"].Should().Be("error1");
    }

    [Fact]
    public void AddError_MultipleCalls_AccumulatesAllErrors()
    {
        var response = new ApiResponse();

        response
            .AddError("emailRequired", "Email is required.")
            .AddError("passwordWeak", "Password too weak.");

        response.IsSuccessful.Should().BeFalse();
        response.Errors.Should().HaveCount(2);
        response.Errors!["emailRequired"].Should().Be("Email is required.");
        response.Errors["passwordWeak"].Should().Be("Password too weak.");
    }

    [Fact]
    public void AddError_DuplicateKey_ThrowsArgumentException()
    {
        // Errors is Dictionary<,> with .Add() — pinned so callers don't expect overwrite.
        var response = new ApiResponse();
        response.AddError("dup", "first");

        var act = () => response.AddError("dup", "second");

        act.Should().Throw<ArgumentException>();
    }

    [Fact]
    public void AddErrors_ManyAtOnce_MergesEveryEntryAndFlipsToUnsuccessful()
    {
        var response = new ApiResponse();
        var batch = new Dictionary<string, string>
        {
            ["PasswordTooShort"] = "Password must be 12+ characters",
            ["PasswordRequiresDigit"] = "Password must contain a digit",
        };

        var returned = response.AddErrors(batch);

        returned.Should().BeSameAs(response);
        response.IsSuccessful.Should().BeFalse();
        response.Errors.Should().HaveCount(2)
            .And.Contain(new KeyValuePair<string, string>("PasswordTooShort", "Password must be 12+ characters"));
    }

    [Fact]
    public void AddErrors_OverwritesExistingKeys_BecauseUsesIndexer()
    {
        // AddErrors uses indexer assignment (overwrites) — intentional asymmetry with AddError.
        var response = new ApiResponse();
        response.AddError("conflict", "original");

        response.AddErrors(new Dictionary<string, string> { ["conflict"] = "overwritten" });

        response.Errors!["conflict"].Should().Be("overwritten");
    }

    [Fact]
    public void Successful_AfterAddError_FlipsBackToTrue()
    {
        // Informational-errors pattern: controller adds non-fatal notes but treats the op as successful.
        var response = new ApiResponse();
        response.AddError("note", "Some informational signal");

        var returned = response.Successful();

        returned.Should().BeSameAs(response);
        response.IsSuccessful.Should().BeTrue();
        response.Errors.Should().NotBeNull(because: "Successful() doesn't clear errors — only re-marks the envelope.");
    }
}
