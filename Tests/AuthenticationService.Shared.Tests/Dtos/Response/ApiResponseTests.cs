using AuthenticationService.Shared.Dtos.Response;
using AwesomeAssertions;

namespace AuthenticationService.Shared.Tests.Dtos.Response;

/// <summary>
/// <para><see cref="ApiResponse"/> is the success/error envelope every API endpoint returns.
/// Its mutation methods (<c>AddError</c>, <c>AddErrors</c>, <c>Successful</c>) are the only
/// way to flip <c>IsSuccessful</c> — and they're called from every controller. Subtle bugs
/// here would either mark genuine errors as success or vice-versa, both of which break
/// clients silently.</para>
///
/// <para>These tests verify every documented behaviour:</para>
/// <list type="bullet">
///   <item><description>Default state is "successful with no errors" — endpoints that don't add an error never need to call <c>Successful()</c>.</description></item>
///   <item><description><c>AddError</c> initialises the dictionary on first call (lazy allocation), flips <c>IsSuccessful</c> to false, and returns <c>this</c> for fluent chaining.</description></item>
///   <item><description><c>AddErrors</c> merges every entry, late writes overwrite earlier ones (Dictionary indexer semantics), still flips <c>IsSuccessful</c>, returns <c>this</c>.</description></item>
///   <item><description><c>Successful()</c> can re-mark a previously-failed response as successful — used in the rare "informational errors" pattern.</description></item>
/// </list>
/// </summary>
public class ApiResponseTests
{
    [Fact]
    public void DefaultState_IsSuccessfulWithNoErrors()
    {
        // arrange / act
        var response = new ApiResponse();

        // assert — endpoints that complete without issue must not have to call anything
        // additional to be considered successful.
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

        // act — keys must be unique because Errors is Dictionary<string, string> with .Add().
        response
            .AddError("emailRequired", "Email is required.")
            .AddError("passwordWeak", "Password too weak.");

        // assert — both errors retained, dictionary not cleared between calls.
        response.IsSuccessful.Should().BeFalse();
        response.Errors.Should().HaveCount(2);
        response.Errors!["emailRequired"].Should().Be("Email is required.");
        response.Errors["passwordWeak"].Should().Be("Password too weak.");
    }

    [Fact]
    public void AddError_DuplicateKey_ThrowsArgumentException()
    {
        // arrange — internal Dictionary<,>.Add throws on duplicate key. Tests document
        // this so callers don't pass duplicates expecting overwrite behaviour.
        var response = new ApiResponse();
        response.AddError("dup", "first");

        // act
        var act = () => response.AddError("dup", "second");

        // assert
        act.Should().Throw<ArgumentException>();
    }

    [Fact]
    public void AddErrors_ManyAtOnce_MergesEveryEntryAndFlipsToUnsuccessful()
    {
        // arrange — typical use: turn an Identity result's errors into our envelope.
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
        // arrange — AddErrors uses indexer assignment so duplicate keys overwrite rather
        // than throw, in contrast to AddError. This is intentional asymmetry; tests
        // document it so callers that rely on it aren't surprised by a future change.
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
        // arrange — informational-errors pattern: the controller adds notes about
        // non-fatal observations but still considers the operation a success.
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
