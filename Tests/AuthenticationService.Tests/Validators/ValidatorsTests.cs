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
        // arrange
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
        // arrange
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
        // arrange
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
        // arrange
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
        // arrange
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
        // arrange — HashSet is OrdinalIgnoreCase so attacker can't bypass the deny-list by changing case.
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
        // arrange — validator trims defensively in case AllowedUserNameCharacters admits leading whitespace.
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
        // arrange
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
        // arrange — missing username isn't this validator's concern, Identity's own rules produce a more useful error.
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
        // arrange
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
        // arrange — only acts on the default-named options instance so future named-options consumers can opt out.
        var environment = StubEnvironment("Production");
        var validator = new AdminAccountSeedSettingsValidator(environment);
        var settings = new AdminAccountSeedSettings
        {
            Email = "a@b.com",
            Password = "Pa5$word123-dev",
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
        // arrange
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
        // arrange — catches the realistic deploy mistake: copy appsettings.Development.json into prod without overriding the password.
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
        // arrange
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
        // arrange — only literal "Development" gets the bypass, every other env triggers the dev-default check.
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

    // ─── ForwardedHeadersSettingsValidator ──────────────────────────────────────────────

    [Fact]
    public void ForwardedHeadersSettingsValidator_NamedInstance_SkipsValidation()
    {
        // arrange
        var validator = new ForwardedHeadersSettingsValidator(StubEnvironment("Production"));
        var settings = new ForwardedHeadersSettings();

        // act
        var result = validator.Validate(name: "namedInstance", settings);

        // assert
        result.Skipped.Should().BeTrue();
    }

    [Fact]
    public void ForwardedHeadersSettingsValidator_Development_AllowsEmptyLists()
    {
        // arrange — local dev with no proxy in front is normal.
        var validator = new ForwardedHeadersSettingsValidator(StubEnvironment("Development"));
        var settings = new ForwardedHeadersSettings();

        // act
        var result = validator.Validate(name: Options.DefaultName, settings);

        // assert
        result.Succeeded.Should().BeTrue();
    }

    [Fact]
    public void ForwardedHeadersSettingsValidator_NonDevelopmentBothEmpty_FailsWithExplicitMessage()
    {
        // arrange — the silent-failure case: deployed behind a proxy, lists empty,
        // X-Forwarded-For ignored, audit logs and rate limiting both blind to client IP.
        var validator = new ForwardedHeadersSettingsValidator(StubEnvironment("Production"));
        var settings = new ForwardedHeadersSettings();

        // act
        var result = validator.Validate(name: Options.DefaultName, settings);

        // assert
        result.Failed.Should().BeTrue();
        result.FailureMessage.Should()
            .Contain("KnownNetworks", because: "operators need the exact setting name to fix it.")
            .And.Contain("KnownProxies")
            .And.Contain("rate-limit", because: "the consequence trips even non-security-minded operators.");
    }

    [Fact]
    public void ForwardedHeadersSettingsValidator_NonDevelopmentKnownNetworksPopulated_Succeeds()
    {
        // arrange — a single CIDR is enough to make the middleware honour the header.
        var validator = new ForwardedHeadersSettingsValidator(StubEnvironment("Production"));
        var settings = new ForwardedHeadersSettings { KnownNetworks = { "10.0.0.0/8" } };

        // act
        var result = validator.Validate(name: Options.DefaultName, settings);

        // assert
        result.Succeeded.Should().BeTrue();
    }

    [Fact]
    public void ForwardedHeadersSettingsValidator_NonDevelopmentKnownProxiesPopulated_Succeeds()
    {
        // arrange — KnownProxies alone is also a valid configuration.
        var validator = new ForwardedHeadersSettingsValidator(StubEnvironment("Production"));
        var settings = new ForwardedHeadersSettings { KnownProxies = { "203.0.113.10" } };

        // act
        var result = validator.Validate(name: Options.DefaultName, settings);

        // assert
        result.Succeeded.Should().BeTrue();
    }

    [Theory]
    [InlineData("Staging")]
    [InlineData("Production")]
    [InlineData("custom-env-name")]
    public void ForwardedHeadersSettingsValidator_AnyNonDevelopmentEnv_TreatsEmptyAsError(string envName)
    {
        // arrange
        var validator = new ForwardedHeadersSettingsValidator(StubEnvironment(envName));
        var settings = new ForwardedHeadersSettings();

        // act
        var result = validator.Validate(name: Options.DefaultName, settings);

        // assert
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
