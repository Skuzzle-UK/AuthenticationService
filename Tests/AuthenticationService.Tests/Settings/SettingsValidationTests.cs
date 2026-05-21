using System.ComponentModel.DataAnnotations;
using AuthenticationService.Settings;
using AwesomeAssertions;

namespace AuthenticationService.Tests.Settings;

/// <summary>
/// Pins DataAnnotation rules on every settings class bound via
/// <c>AddOptions&lt;T&gt;.ValidateDataAnnotations().ValidateOnStart()</c> — those rules
/// are the deploy-time gate against operator misconfiguration.
/// </summary>
public class SettingsValidationTests
{
    // ─── JWTSettings ────────────────────────────────────────────────────────────────────

    [Fact]
    public void JWTSettings_FullyPopulated_Passes()
    {
        var settings = new JWTSettings
        {
            PrivateKeyDirectory = "keys",
            ValidIssuer = "https://auth.example.com",
            ValidAudience = "platform-api",
            ExpiryInMinutes = 15,
            RefreshTokenExpiryInDays = 14,
        };

        Validate(settings).Should().BeEmpty();
    }

    [Theory]
    [InlineData(nameof(JWTSettings.PrivateKeyDirectory))]
    [InlineData(nameof(JWTSettings.ValidIssuer))]
    [InlineData(nameof(JWTSettings.ValidAudience))]
    public void JWTSettings_RequiredFieldMissing_Fails(string field)
    {
        var settings = new JWTSettings
        {
            PrivateKeyDirectory = "keys",
            ValidIssuer = "https://auth.example.com",
            ValidAudience = "platform-api",
            ExpiryInMinutes = 15,
            RefreshTokenExpiryInDays = 14,
        };
        switch (field)
        {
            case nameof(JWTSettings.PrivateKeyDirectory): settings.PrivateKeyDirectory = null!; break;
            case nameof(JWTSettings.ValidIssuer): settings.ValidIssuer = null!; break;
            case nameof(JWTSettings.ValidAudience): settings.ValidAudience = null!; break;
        }

        var results = Validate(settings);

        results.Should().Contain(r => r.MemberNames.Contains(field));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(-5)]
    [InlineData(1441)]
    public void JWTSettings_ExpiryInMinutesOutOfRange_Fails(int minutes)
    {
        var settings = new JWTSettings
        {
            PrivateKeyDirectory = "keys",
            ValidIssuer = "i",
            ValidAudience = "a",
            ExpiryInMinutes = minutes,
            RefreshTokenExpiryInDays = 14,
        };

        var results = Validate(settings);

        results.Should().Contain(r => r.MemberNames.Contains(nameof(JWTSettings.ExpiryInMinutes)));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(-1)]
    [InlineData(366)]
    public void JWTSettings_RefreshTokenExpiryInDaysOutOfRange_Fails(int days)
    {
        var settings = new JWTSettings
        {
            PrivateKeyDirectory = "keys",
            ValidIssuer = "i",
            ValidAudience = "a",
            ExpiryInMinutes = 15,
            RefreshTokenExpiryInDays = days,
        };

        var results = Validate(settings);

        results.Should().Contain(r => r.MemberNames.Contains(nameof(JWTSettings.RefreshTokenExpiryInDays)));
    }

    [Fact]
    public void JWTSettings_ActiveKeyId_DefaultsToAuto()
    {
        // "auto" sentinel means "pick first key in the directory."
        var settings = new JWTSettings();

        settings.ActiveKeyId.Should().Be("auto");
    }

    // ─── IdentitySettings (nested) ──────────────────────────────────────────────────────

    [Fact]
    public void PasswordSettings_Defaults_MatchNistGuidance()
    {
        // Defaults should equal NIST 800-63B / OWASP guidance — silent loosening would weaken every deployment.
        var settings = new PasswordSettings();

        settings.RequiredLength.Should().Be(12);
        settings.RequireDigit.Should().BeTrue();
        settings.RequireLowercase.Should().BeTrue();
        settings.RequireUppercase.Should().BeTrue();
        settings.RequireNonAlphanumeric.Should().BeTrue();
        settings.RequiredUniqueChars.Should().Be(1);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(-1)]
    [InlineData(257)]
    public void PasswordSettings_RequiredLengthOutOfRange_Fails(int length)
    {
        var settings = new PasswordSettings { RequiredLength = length };

        var results = Validate(settings);

        results.Should().Contain(r => r.MemberNames.Contains(nameof(PasswordSettings.RequiredLength)));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(257)]
    public void PasswordSettings_RequiredUniqueCharsOutOfRange_Fails(int chars)
    {
        var settings = new PasswordSettings { RequiredUniqueChars = chars };

        var results = Validate(settings);

        results.Should().Contain(r => r.MemberNames.Contains(nameof(PasswordSettings.RequiredUniqueChars)));
    }

    [Fact]
    public void UserSettings_Defaults_RequireUniqueEmailAndPermissiveCharacterSet()
    {
        var settings = new UserSettings();

        settings.RequireUniqueEmail.Should().BeTrue();
        settings.AllowedUserNameCharacters
            .Should().Be("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._@+");
        settings.ReservedUserNames.Should().NotBeEmpty(because: "platform reserves admin-adjacent names.");
    }

    [Fact]
    public void LockoutSettings_Defaults_AllowedForNewUsersAndAggressive()
    {
        // Defaults are the security baseline: lockout on, 3 attempts, 2 minutes.
        var settings = new LockoutSettings();

        settings.AllowedForNewUsers.Should().BeTrue();
        settings.DefaultLockoutDurationInMinutes.Should().Be(2);
        settings.MaxFailedAccessAttempts.Should().Be(3);
    }

    [Theory]
    [InlineData(0.05)]
    [InlineData(1441)]
    public void LockoutSettings_DefaultLockoutDurationOutOfRange_Fails(double minutes)
    {
        var settings = new LockoutSettings { DefaultLockoutDurationInMinutes = minutes };

        var results = Validate(settings);

        results.Should().Contain(r => r.MemberNames.Contains(nameof(LockoutSettings.DefaultLockoutDurationInMinutes)));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(101)]
    public void LockoutSettings_MaxFailedAccessAttemptsOutOfRange_Fails(int attempts)
    {
        var settings = new LockoutSettings { MaxFailedAccessAttempts = attempts };

        var results = Validate(settings);

        results.Should().Contain(r => r.MemberNames.Contains(nameof(LockoutSettings.MaxFailedAccessAttempts)));
    }

    // ─── AdminAccountSeedSettings ───────────────────────────────────────────────────────

    [Fact]
    public void AdminAccountSeedSettings_FullyPopulated_Passes()
    {
        var settings = new AdminAccountSeedSettings
        {
            Email = "admin@example.com",
            Password = "AdminPass!1234",
            FirstName = "Admin",
        };

        Validate(settings).Should().BeEmpty();
    }

    [Theory]
    [InlineData(nameof(AdminAccountSeedSettings.Email))]
    [InlineData(nameof(AdminAccountSeedSettings.Password))]
    [InlineData(nameof(AdminAccountSeedSettings.FirstName))]
    public void AdminAccountSeedSettings_RequiredFieldMissing_Fails(string field)
    {
        var settings = new AdminAccountSeedSettings
        {
            Email = "admin@example.com",
            Password = "AdminPass!",
            FirstName = "Admin",
        };
        switch (field)
        {
            case nameof(AdminAccountSeedSettings.Email): settings.Email = null!; break;
            case nameof(AdminAccountSeedSettings.Password): settings.Password = null!; break;
            case nameof(AdminAccountSeedSettings.FirstName): settings.FirstName = null!; break;
        }

        var results = Validate(settings);

        results.Should().Contain(r => r.MemberNames.Contains(field));
    }

    [Fact]
    public void AdminAccountSeedSettings_InvalidEmail_Fails()
    {
        var settings = new AdminAccountSeedSettings { Email = "not-email", Password = "p", FirstName = "A" };

        var results = Validate(settings);

        results.Should().Contain(r => r.MemberNames.Contains(nameof(AdminAccountSeedSettings.Email)));
    }

    [Theory]
    [InlineData(nameof(AdminAccountSeedSettings.FirstName), 51)]
    [InlineData(nameof(AdminAccountSeedSettings.LastName), 51)]
    [InlineData(nameof(AdminAccountSeedSettings.Country), 61)]
    public void AdminAccountSeedSettings_LengthBoundedFieldOverLength_Fails(string field, int overLength)
    {
        var oversize = new string('x', overLength);
        var settings = new AdminAccountSeedSettings { Email = "a@b.com", Password = "p", FirstName = "A" };
        switch (field)
        {
            case nameof(AdminAccountSeedSettings.FirstName): settings.FirstName = oversize; break;
            case nameof(AdminAccountSeedSettings.LastName): settings.LastName = oversize; break;
            case nameof(AdminAccountSeedSettings.Country): settings.Country = oversize; break;
        }

        var results = Validate(settings);

        results.Should().Contain(r => r.MemberNames.Contains(field));
    }

    [Fact]
    public void AdminAccountSeedSettings_PhoneNumberMalformed_Fails()
    {
        var settings = new AdminAccountSeedSettings
        {
            Email = "a@b.com",
            Password = "p",
            FirstName = "A",
            PhoneNumber = "obviously-not-a-phone",
        };

        var results = Validate(settings);

        results.Should().Contain(r => r.MemberNames.Contains(nameof(AdminAccountSeedSettings.PhoneNumber)));
    }

    // ─── HostingSettings ────────────────────────────────────────────────────────────────

    [Fact]
    public void HostingSettings_Defaults_BackgroundWorkersOnAndOneMbBodyCap()
    {
        var settings = new HostingSettings();

        settings.BackgroundWorkersEnabled.Should().BeTrue();
        settings.MaxRequestBodySizeInKilobytes.Should().Be(1024);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(-1)]
    [InlineData(30_721)]
    public void HostingSettings_MaxRequestBodySizeInKilobytesOutOfRange_Fails(int kb)
    {
        var settings = new HostingSettings { MaxRequestBodySizeInKilobytes = kb };

        var results = Validate(settings);

        results.Should().Contain(r => r.MemberNames.Contains(nameof(HostingSettings.MaxRequestBodySizeInKilobytes)));
    }

    // ─── ThresholdEscalationSettings (defaults — no annotations) ────────────────────────

    [Fact]
    public void ThresholdEscalationSettings_Defaults_AggressiveButForgiving()
    {
        var settings = new ThresholdEscalationSettings();

        settings.Enabled.Should().BeTrue();
        settings.SweepIntervalInMinutes.Should().Be(1);
        settings.WindowInMinutes.Should().Be(5);
        settings.WarnThreshold.Should().Be(2);
        settings.LockThreshold.Should().Be(5);
    }

    // ─── DataRetentionSettings (defaults — no annotations) ──────────────────────────────

    [Fact]
    public void DataRetentionSettings_Defaults_TwelveHourSweepNinetyDayTtl()
    {
        var settings = new DataRetentionSettings();

        settings.CleanupIntervalInHours.Should().Be(12);
        settings.RevokedReplayTTLInDays.Should().Be(90);
    }

    private static List<ValidationResult> Validate(object instance)
    {
        var results = new List<ValidationResult>();
        Validator.TryValidateObject(instance, new ValidationContext(instance), results, validateAllProperties: true);
        return results;
    }
}
