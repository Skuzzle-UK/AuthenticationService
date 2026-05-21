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
/// Exercises every branch of the three custom validators on the registration / settings-binding paths.
/// </summary>
public class ValidatorsTests
{
    // ─── CustomPasswordValidator ────────────────────────────────────────────────────────

    [Fact]
    public async Task CustomPasswordValidator_PasswordMatchesUsername_ReturnsSameUserPassError()
    {
        var user = new User { UserName = "alice", Email = "alice@example.com" };
        var manager = StubUserManager(userName: "alice", email: "alice@example.com");
        var validator = new CustomPasswordValidator<User>();

        var result = await validator.ValidateAsync(manager, user, "alice");

        result.Succeeded.Should().BeFalse();
        result.Errors.Should().ContainSingle(e =>
            e.Code == "SameUserPass" && e.Description.Contains("Username and Password can not be the same"));
    }

    [Fact]
    public async Task CustomPasswordValidator_PasswordMatchesUsernameCaseInsensitive_StillFails()
    {
        var user = new User { UserName = "alice", Email = "alice@example.com" };
        var manager = StubUserManager(userName: "alice", email: "alice@example.com");
        var validator = new CustomPasswordValidator<User>();

        var result = await validator.ValidateAsync(manager, user, "ALICE");

        result.Succeeded.Should().BeFalse();
        result.Errors.Should().ContainSingle(e => e.Code == "SameUserPass");
    }

    [Fact]
    public async Task CustomPasswordValidator_PasswordMatchesEmail_ReturnsSameEmailPassError()
    {
        var user = new User { UserName = "alice", Email = "alice@example.com" };
        var manager = StubUserManager(userName: "alice", email: "alice@example.com");
        var validator = new CustomPasswordValidator<User>();

        var result = await validator.ValidateAsync(manager, user, "alice@example.com");

        result.Succeeded.Should().BeFalse();
        result.Errors.Should().ContainSingle(e =>
            e.Code == "SameEmailPass" && e.Description.Contains("Email and Password can not be the same"));
    }

    [Fact]
    public async Task CustomPasswordValidator_PasswordDifferentFromUsernameAndEmail_Succeeds()
    {
        var user = new User { UserName = "alice", Email = "alice@example.com" };
        var manager = StubUserManager(userName: "alice", email: "alice@example.com");
        var validator = new CustomPasswordValidator<User>();

        var result = await validator.ValidateAsync(manager, user, "Sup3rSecur3!");

        result.Succeeded.Should().BeTrue();
    }

    // ─── ReservedUserNameValidator ──────────────────────────────────────────────────────

    [Fact]
    public async Task ReservedUserNameValidator_ReservedName_FailsWithReservedUserNameError()
    {
        var settings = MakeIdentitySettings(["administrator", "root", "support"]);
        var validator = new ReservedUserNameValidator(settings);
        var user = new User { UserName = "administrator" };

        var result = await validator.ValidateAsync(StubUserManager(), user);

        result.Succeeded.Should().BeFalse();
        result.Errors.Should().ContainSingle(e =>
            e.Code == "ReservedUserName"
            && e.Description.Contains("reserved"));
    }

    [Fact]
    public async Task ReservedUserNameValidator_ReservedNameDifferentCasing_StillFails()
    {
        // HashSet is OrdinalIgnoreCase so attacker can't bypass the deny-list by changing case.
        var settings = MakeIdentitySettings(["administrator"]);
        var validator = new ReservedUserNameValidator(settings);
        var user = new User { UserName = "Administrator" };

        var result = await validator.ValidateAsync(StubUserManager(), user);

        result.Succeeded.Should().BeFalse();
    }

    [Fact]
    public async Task ReservedUserNameValidator_ReservedNameWithSurroundingWhitespace_StillFails()
    {
        // Validator trims defensively in case AllowedUserNameCharacters admits leading whitespace.
        var settings = MakeIdentitySettings(["root"]);
        var validator = new ReservedUserNameValidator(settings);
        var user = new User { UserName = "  root  " };

        var result = await validator.ValidateAsync(StubUserManager(), user);

        result.Succeeded.Should().BeFalse();
    }

    [Fact]
    public async Task ReservedUserNameValidator_NonReservedName_Succeeds()
    {
        var settings = MakeIdentitySettings(["administrator", "root"]);
        var validator = new ReservedUserNameValidator(settings);
        var user = new User { UserName = "alice" };

        var result = await validator.ValidateAsync(StubUserManager(), user);

        result.Succeeded.Should().BeTrue();
    }

    [Fact]
    public async Task ReservedUserNameValidator_NullOrWhitespaceUserName_TreatedAsNotReserved()
    {
        // Missing username isn't this validator's concern — Identity's own rules produce a more useful error.
        var settings = MakeIdentitySettings(["root"]);
        var validator = new ReservedUserNameValidator(settings);
        var user = new User { UserName = null };

        var result = await validator.ValidateAsync(StubUserManager(), user);

        result.Succeeded.Should().BeTrue();
    }

    [Fact]
    public async Task ReservedUserNameValidator_EmptyDenyList_NeverFails()
    {
        var settings = MakeIdentitySettings([]);
        var validator = new ReservedUserNameValidator(settings);
        var user = new User { UserName = "administrator" };

        var result = await validator.ValidateAsync(StubUserManager(), user);

        result.Succeeded.Should().BeTrue();
    }

    // ─── AdminAccountSeedSettingsValidator ──────────────────────────────────────────────

    [Fact]
    public void AdminAccountSeedSettingsValidator_NamedInstance_SkipsValidation()
    {
        // Only acts on the default-named options instance so future named-options consumers can opt out.
        var environment = StubEnvironment("Production");
        var validator = new AdminAccountSeedSettingsValidator(environment);
        var settings = new AdminAccountSeedSettings
        {
            Email = "a@b.com",
            Password = "Pa5$word123-dev",
            FirstName = "A",
        };

        var result = validator.Validate(name: "namedInstance", settings);

        result.Skipped.Should().BeTrue();
    }

    [Fact]
    public void AdminAccountSeedSettingsValidator_DevelopmentEnvironment_AllowsDevDefault()
    {
        var environment = StubEnvironment("Development");
        var validator = new AdminAccountSeedSettingsValidator(environment);
        var settings = new AdminAccountSeedSettings
        {
            Email = "a@b.com",
            Password = "Pa5$word123-dev",
            FirstName = "A",
        };

        var result = validator.Validate(name: Options.DefaultName, settings);

        result.Succeeded.Should().BeTrue();
    }

    [Fact]
    public void AdminAccountSeedSettingsValidator_NonDevelopmentWithDevDefaultPassword_FailsWithExplicitMessage()
    {
        // Catches the realistic deploy mistake: copy appsettings.Development.json into prod without overriding the password.
        var environment = StubEnvironment("Production");
        var validator = new AdminAccountSeedSettingsValidator(environment);
        var settings = new AdminAccountSeedSettings
        {
            Email = "a@b.com",
            Password = "Pa5$word123-dev",
            FirstName = "A",
        };

        var result = validator.Validate(name: Options.DefaultName, settings);

        result.Failed.Should().BeTrue();
        result.FailureMessage.Should().Contain("development default")
            .And.Contain("AdminAccountSeedSettings__Password",
                because: "operators read the failure message and must see the exact env-var name to fix the issue.");
    }

    [Fact]
    public void AdminAccountSeedSettingsValidator_NonDevelopmentWithCustomPassword_Succeeds()
    {
        var environment = StubEnvironment("Production");
        var validator = new AdminAccountSeedSettingsValidator(environment);
        var settings = new AdminAccountSeedSettings
        {
            Email = "a@b.com",
            Password = "Pr0d!Pa$$w0rd1234",
            FirstName = "A",
        };

        var result = validator.Validate(name: Options.DefaultName, settings);

        result.Succeeded.Should().BeTrue();
    }

    [Theory]
    [InlineData("Staging")]
    [InlineData("QA")]
    [InlineData("CustomEnv")]
    public void AdminAccountSeedSettingsValidator_AnyNonDevelopmentEnvironment_AppliesRule(string envName)
    {
        // Only literal "Development" gets the bypass — every other env triggers the dev-default check.
        var environment = StubEnvironment(envName);
        var validator = new AdminAccountSeedSettingsValidator(environment);
        var settings = new AdminAccountSeedSettings
        {
            Email = "a@b.com",
            Password = "Pa5$word123-dev",
            FirstName = "A",
        };

        var result = validator.Validate(name: Options.DefaultName, settings);

        result.Failed.Should().BeTrue();
    }

    // ─── helpers ────────────────────────────────────────────────────────────────────────

    private static UserManager<User> StubUserManager(string? userName = null, string? email = null)
    {
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
