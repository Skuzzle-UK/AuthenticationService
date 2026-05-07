using AuthenticationService.Entities;
using AuthenticationService.Settings;
using AuthenticationService.Validators;
using AwesomeAssertions;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;
using NSubstitute;

namespace AuthenticationService.Tests.Validators;

/// <summary>
/// <para>The three validators sit on the registration / settings-binding paths and act as
/// the canonical "no" for input that shouldn't reach the database. Every branch of every
/// validator is exercised here so a regression that loosens any rule gets caught.</para>
/// </summary>
public class ValidatorsTests
{
    // ─── CustomPasswordValidator ────────────────────────────────────────────────────────

    /// <summary>
    /// <para>Hooked into Identity's password-validator chain at registration / change-password
    /// time. Rejects passwords that match the user's own username or email — the trivially
    /// most common dictionary-attack starting point. Three paths exist:</para>
    /// <list type="bullet">
    ///   <item><description>password matches username (case-insensitive) → fail with code SameUserPass</description></item>
    ///   <item><description>password matches email (case-insensitive) → fail with code SameEmailPass</description></item>
    ///   <item><description>neither match → success (Identity's other validators still run)</description></item>
    /// </list>
    /// </summary>
    [Fact]
    public async Task CustomPasswordValidator_PasswordMatchesUsername_ReturnsSameUserPassError()
    {
        // arrange — exact match (the validator is case-insensitive but we test exact first
        // to verify the basic match works).
        var user = new User { UserName = "alice", Email = "alice@example.com" };
        var manager = StubUserManager(userName: "alice", email: "alice@example.com");
        var validator = new CustomPasswordValidator<User>();

        // act
        var result = await validator.ValidateAsync(manager, user, "alice");

        // assert
        result.Succeeded.Should().BeFalse();
        result.Errors.Should().ContainSingle(e =>
            e.Code == "SameUserPass" && e.Description.Contains("Username and Password can not be the same"));
    }

    [Fact]
    public async Task CustomPasswordValidator_PasswordMatchesUsernameCaseInsensitive_StillFails()
    {
        // arrange — case-insensitive comparison: ALICE == alice.
        var user = new User { UserName = "alice", Email = "alice@example.com" };
        var manager = StubUserManager(userName: "alice", email: "alice@example.com");
        var validator = new CustomPasswordValidator<User>();

        // act
        var result = await validator.ValidateAsync(manager, user, "ALICE");

        // assert
        result.Succeeded.Should().BeFalse();
        result.Errors.Should().ContainSingle(e => e.Code == "SameUserPass");
    }

    [Fact]
    public async Task CustomPasswordValidator_PasswordMatchesEmail_ReturnsSameEmailPassError()
    {
        // arrange — username doesn't match, email does.
        var user = new User { UserName = "alice", Email = "alice@example.com" };
        var manager = StubUserManager(userName: "alice", email: "alice@example.com");
        var validator = new CustomPasswordValidator<User>();

        // act
        var result = await validator.ValidateAsync(manager, user, "alice@example.com");

        // assert
        result.Succeeded.Should().BeFalse();
        result.Errors.Should().ContainSingle(e =>
            e.Code == "SameEmailPass" && e.Description.Contains("Email and Password can not be the same"));
    }

    [Fact]
    public async Task CustomPasswordValidator_PasswordDifferentFromUsernameAndEmail_Succeeds()
    {
        // arrange — happy path. Identity's other validators still run on top; this one
        // just opts in to "no obvious dictionary attack."
        var user = new User { UserName = "alice", Email = "alice@example.com" };
        var manager = StubUserManager(userName: "alice", email: "alice@example.com");
        var validator = new CustomPasswordValidator<User>();

        // act
        var result = await validator.ValidateAsync(manager, user, "Sup3rSecur3!");

        // assert
        result.Succeeded.Should().BeTrue();
    }

    // ─── ReservedUserNameValidator ──────────────────────────────────────────────────────

    [Fact]
    public async Task ReservedUserNameValidator_ReservedName_FailsWithReservedUserNameError()
    {
        // arrange — "administrator" is on the platform-default deny-list.
        var settings = MakeIdentitySettings(["administrator", "root", "support"]);
        var validator = new ReservedUserNameValidator(settings);
        var user = new User { UserName = "administrator" };

        // act
        var result = await validator.ValidateAsync(StubUserManager(), user);

        // assert
        result.Succeeded.Should().BeFalse();
        result.Errors.Should().ContainSingle(e =>
            e.Code == "ReservedUserName"
            && e.Description.Contains("reserved"));
    }

    [Fact]
    public async Task ReservedUserNameValidator_ReservedNameDifferentCasing_StillFails()
    {
        // arrange — HashSet is OrdinalIgnoreCase, so "ADMINISTRATOR" vs "administrator"
        // matches. Otherwise an attacker just changes case to bypass the deny-list.
        var settings = MakeIdentitySettings(["administrator"]);
        var validator = new ReservedUserNameValidator(settings);
        var user = new User { UserName = "Administrator" };

        // act
        var result = await validator.ValidateAsync(StubUserManager(), user);

        // assert
        result.Succeeded.Should().BeFalse();
    }

    [Fact]
    public async Task ReservedUserNameValidator_ReservedNameWithSurroundingWhitespace_StillFails()
    {
        // arrange — Identity's allowed-character rules might admit a leading space
        // depending on the AllowedUserNameCharacters setting; the validator trims defensively.
        var settings = MakeIdentitySettings(["root"]);
        var validator = new ReservedUserNameValidator(settings);
        var user = new User { UserName = "  root  " };

        // act
        var result = await validator.ValidateAsync(StubUserManager(), user);

        // assert
        result.Succeeded.Should().BeFalse();
    }

    [Fact]
    public async Task ReservedUserNameValidator_NonReservedName_Succeeds()
    {
        // arrange — happy path: regular user picking an arbitrary username.
        var settings = MakeIdentitySettings(["administrator", "root"]);
        var validator = new ReservedUserNameValidator(settings);
        var user = new User { UserName = "alice" };

        // act
        var result = await validator.ValidateAsync(StubUserManager(), user);

        // assert
        result.Succeeded.Should().BeTrue();
    }

    [Fact]
    public async Task ReservedUserNameValidator_NullOrWhitespaceUserName_TreatedAsNotReserved()
    {
        // arrange — a missing username isn't this validator's concern (Identity's own
        // RequireUniqueEmail / username-length rules handle that). Returning Success here
        // means the chain continues to those other validators that produce more useful
        // errors. A regression that returns Failed("reserved") for null would surface a
        // misleading error message.
        var settings = MakeIdentitySettings(["root"]);
        var validator = new ReservedUserNameValidator(settings);
        var user = new User { UserName = null };

        // act
        var result = await validator.ValidateAsync(StubUserManager(), user);

        // assert
        result.Succeeded.Should().BeTrue();
    }

    [Fact]
    public async Task ReservedUserNameValidator_EmptyDenyList_NeverFails()
    {
        // arrange — operator clears the deny-list (e.g., for testing). Validator must not
        // throw or produce false positives.
        var settings = MakeIdentitySettings([]);
        var validator = new ReservedUserNameValidator(settings);
        var user = new User { UserName = "administrator" };

        // act
        var result = await validator.ValidateAsync(StubUserManager(), user);

        // assert
        result.Succeeded.Should().BeTrue();
    }

    // ─── AdminAccountSeedSettingsValidator ──────────────────────────────────────────────

    [Fact]
    public void AdminAccountSeedSettingsValidator_NamedInstance_SkipsValidation()
    {
        // arrange — the validator only acts on the default-named options instance. This
        // is so future named-options consumers can opt out of the dev-default rule.
        var environment = StubEnvironment("Production");
        var validator = new AdminAccountSeedSettingsValidator(environment);
        var settings = new AdminAccountSeedSettings
        {
            Email = "a@b.com",
            Password = "Pa5$word123-dev", // would normally fail
            FirstName = "A",
        };

        // act
        var result = validator.Validate(name: "namedInstance", settings);

        // assert
        result.Skipped.Should().BeTrue();
    }

    [Fact]
    public void AdminAccountSeedSettingsValidator_DevelopmentEnvironment_AllowsDevDefault()
    {
        // arrange — Development is allowed to ship with the bundled default password
        // (matches what's in appsettings.Development.json).
        var environment = StubEnvironment("Development");
        var validator = new AdminAccountSeedSettingsValidator(environment);
        var settings = new AdminAccountSeedSettings
        {
            Email = "a@b.com",
            Password = "Pa5$word123-dev",
            FirstName = "A",
        };

        // act
        var result = validator.Validate(name: Options.DefaultName, settings);

        // assert
        result.Succeeded.Should().BeTrue();
    }

    [Fact]
    public void AdminAccountSeedSettingsValidator_NonDevelopmentWithDevDefaultPassword_FailsWithExplicitMessage()
    {
        // arrange — the realistic deploy mistake the validator exists to catch: copy
        // appsettings.Development.json into prod without overriding the password.
        var environment = StubEnvironment("Production");
        var validator = new AdminAccountSeedSettingsValidator(environment);
        var settings = new AdminAccountSeedSettings
        {
            Email = "a@b.com",
            Password = "Pa5$word123-dev",
            FirstName = "A",
        };

        // act
        var result = validator.Validate(name: Options.DefaultName, settings);

        // assert
        result.Failed.Should().BeTrue();
        result.FailureMessage.Should().Contain("development default")
            .And.Contain("AdminAccountSeedSettings__Password",
                because: "operators read the failure message and must see the exact env-var name to fix the issue.");
    }

    [Fact]
    public void AdminAccountSeedSettingsValidator_NonDevelopmentWithCustomPassword_Succeeds()
    {
        // arrange — operator did the right thing and supplied a real password via env var.
        var environment = StubEnvironment("Production");
        var validator = new AdminAccountSeedSettingsValidator(environment);
        var settings = new AdminAccountSeedSettings
        {
            Email = "a@b.com",
            Password = "Pr0d!Pa$$w0rd1234",
            FirstName = "A",
        };

        // act
        var result = validator.Validate(name: Options.DefaultName, settings);

        // assert
        result.Succeeded.Should().BeTrue();
    }

    [Theory]
    [InlineData("Staging")]
    [InlineData("QA")]
    [InlineData("CustomEnv")]
    public void AdminAccountSeedSettingsValidator_AnyNonDevelopmentEnvironment_AppliesRule(string envName)
    {
        // arrange — only the literal "Development" gets the bypass. Any other environment
        // name triggers the dev-default check.
        var environment = StubEnvironment(envName);
        var validator = new AdminAccountSeedSettingsValidator(environment);
        var settings = new AdminAccountSeedSettings
        {
            Email = "a@b.com",
            Password = "Pa5$word123-dev",
            FirstName = "A",
        };

        // act
        var result = validator.Validate(name: Options.DefaultName, settings);

        // assert
        result.Failed.Should().BeTrue();
    }

    // ─── helpers ────────────────────────────────────────────────────────────────────────

    private static UserManager<User> StubUserManager(string? userName = null, string? email = null)
    {
        // arrange — UserManager is hard to construct properly. Use NSubstitute.For with a
        // minimal IUserStore + nulls for the rest. The validator only calls
        // GetUserNameAsync and GetEmailAsync, both of which we configure here.
        var store = Substitute.For<IUserStore<User>>();
        var manager = Substitute.For<UserManager<User>>(store, null!, null!, null!, null!, null!, null!, null!, null!);
        manager.GetUserNameAsync(Arg.Any<User>()).Returns(userName);
        manager.GetEmailAsync(Arg.Any<User>()).Returns(email);
        return manager;
    }

    private static IOptions<IdentitySettings> MakeIdentitySettings(IEnumerable<string> reserved) =>
        Options.Create(new IdentitySettings
        {
            User = new UserSettings { ReservedUserNames = reserved.ToList() },
        });

    private static IHostEnvironment StubEnvironment(string envName)
    {
        var env = Substitute.For<IHostEnvironment>();
        env.EnvironmentName.Returns(envName);
        return env;
    }
}
