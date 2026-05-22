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
        // arrange
        var response = new ApiResponse();

        // assert
        response.IsSuccessful.Should().BeTrue();
        response.Errors.Should().BeNull();
    }

    [Fact]
    public void AddError_FirstCall_AllocatesDictionaryAndFlipsToUnsuccessful()
    {
        // arrange
        var response = new ApiResponse();

        // act
        var returned = response.AddError("key1", "error1");

        // assert
        returned.Should().BeSameAs(response, because: "fluent chaining contract");
        response.IsSuccessful.Should().BeFalse();
        response.Errors.Should().NotBeNull().And.ContainKey("key1");
        response.Errors!["key1"].Should().Be("error1");
    }

    [Fact]
    public void AddError_MultipleCalls_AccumulatesAllErrors()
    {
        // arrange
        var response = new ApiResponse();

        // act
        response
            .AddError("emailRequired", "Email is required.")
            .AddError("passwordWeak", "Password too weak.");

        // assert
        response.IsSuccessful.Should().BeFalse();
        response.Errors.Should().HaveCount(2);
        response.Errors!["emailRequired"].Should().Be("Email is required.");
        response.Errors["passwordWeak"].Should().Be("Password too weak.");
    }

    [Fact]
    public void AddError_DuplicateKey_ThrowsArgumentException()
    {
        // arrange — Errors is Dictionary<,> with .Add(); pinned so callers don't expect overwrite.
        var response = new ApiResponse();
        response.AddError("dup", "first");

        // act + assert
        var act = () => response.AddError("dup", "second");

        act.Should().Throw<ArgumentException>();
    }

    [Fact]
    public void AddErrors_ManyAtOnce_MergesEveryEntryAndFlipsToUnsuccessful()
    {
        // arrange
        var response = new ApiResponse();
        var batch = new Dictionary<string, string>
        {
            ["PasswordTooShort"] = "Password must be 12+ characters",
            ["PasswordRequiresDigit"] = "Password must contain a digit",
        };

        // act
        var returned = response.AddErrors(batch);

        // assert
        returned.Should().BeSameAs(response);
        response.IsSuccessful.Should().BeFalse();
        response.Errors.Should().HaveCount(2)
            .And.Contain(new KeyValuePair<string, string>("PasswordTooShort", "Password must be 12+ characters"));
    }

    [Fact]
    public void AddErrors_OverwritesExistingKeys_BecauseUsesIndexer()
    {
        // arrange — AddErrors uses indexer assignment (overwrites); intentional asymmetry with AddError.
        var response = new ApiResponse();
        response.AddError("conflict", "original");

        // act
        response.AddErrors(new Dictionary<string, string> { ["conflict"] = "overwritten" });

        // assert
        response.Errors!["conflict"].Should().Be("overwritten");
    }

    [Fact]
    public void Successful_AfterAddError_FlipsBackToTrue()
    {
        // arrange — informational-errors pattern: controller adds non-fatal notes but treats the op as successful.
        var response = new ApiResponse();
        response.AddError("note", "Some informational signal");

        // act
        var returned = response.Successful();

        // assert
        returned.Should().BeSameAs(response);
        response.IsSuccessful.Should().BeTrue();
        response.Errors.Should().NotBeNull(because: "Successful() doesn't clear errors — only re-marks the envelope.");
    }
}
