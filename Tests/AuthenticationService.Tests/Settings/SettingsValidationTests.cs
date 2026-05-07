using System.ComponentModel.DataAnnotations;
using AuthenticationService.Settings;
using AwesomeAssertions;

namespace AuthenticationService.Tests.Settings;

/// <summary>
/// <para>Every settings class is bound via <c>AddOptions&lt;T&gt;.ValidateDataAnnotations().ValidateOnStart()</c>
/// in <c>HostExtensions</c>, so DataAnnotation rules act as the deploy-time gate against
/// operator misconfiguration. These tests pin each rule by exercising the success path
/// and every constraint a misconfigured operator might trip.</para>
///
/// <para>Settings covered: <see cref="JWTSettings"/>, <see cref="IdentitySettings"/> +
/// nested types, <see cref="AdminAccountSeedSettings"/>, <see cref="HostingSettings"/>.
/// Settings without DataAnnotations (<see cref="DataRetentionSettings"/>,
/// <see cref="ThresholdEscalationSettings"/>, <see cref="CorsSettings"/>,
/// <see cref="ForwardedHeadersSettings"/>, <see cref="PublicUrlSettings"/>,
/// <see cref="DataProtectionSettings"/>, <see cref="DataProtectionCertificateSettings"/>,
/// <see cref="EmailServerSettings"/>) are spot-checked for default values where defaults
/// are load-bearing.</para>
/// </summary>
public class SettingsValidationTests
{
    // ─── JWTSettings ────────────────────────────────────────────────────────────────────

    [Fact]
    public void JWTSettings_FullyPopulated_Passes()
    {
        // arrange — minimum production-shaped config.
        var settings = new JWTSettings
        {
            PrivateKeyDirectory = "keys",
            ValidIssuer = "https://auth.example.com",
            ValidAudience = "platform-api",
            ExpiryInMinutes = 15,
            RefreshTokenExpiryInDays = 14,
        };

        // act / assert
        Validate(settings).Should().BeEmpty();
    }

    [Theory]
    [InlineData(nameof(JWTSettings.PrivateKeyDirectory))]
    [InlineData(nameof(JWTSettings.ValidIssuer))]
    [InlineData(nameof(JWTSettings.ValidAudience))]
    public void JWTSettings_RequiredFieldMissing_Fails(string field)
    {
        // arrange — these are deploy-blocking; the service can't sign without a key dir
        // and consumers reject tokens with a missing iss/aud.
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

        // act
        var results = Validate(settings);

        // assert
        results.Should().Contain(r => r.MemberNames.Contains(field));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(-5)]
    [InlineData(1441)]
    public void JWTSettings_ExpiryInMinutesOutOfRange_Fails(int minutes)
    {
        // arrange — Range(1, 1440). 0 / negative would mean "instantly expired";
        // > 24 hours violates the short-access-token policy this service is built on.
        var settings = new JWTSettings
        {
            PrivateKeyDirectory = "keys",
            ValidIssuer = "i",
            ValidAudience = "a",
            ExpiryInMinutes = minutes,
            RefreshTokenExpiryInDays = 14,
        };

        // act
        var results = Validate(settings);

        // assert
        results.Should().Contain(r => r.MemberNames.Contains(nameof(JWTSettings.ExpiryInMinutes)));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(-1)]
    [InlineData(366)]
    public void JWTSettings_RefreshTokenExpiryInDaysOutOfRange_Fails(int days)
    {
        // arrange — Range(1, 365). Refresh tokens beyond a year are an excessive session
        // lifetime; below 1 day breaks the typical refresh cadence.
        var settings = new JWTSettings
        {
            PrivateKeyDirectory = "keys",
            ValidIssuer = "i",
            ValidAudience = "a",
            ExpiryInMinutes = 15,
            RefreshTokenExpiryInDays = days,
        };

        // act
        var results = Validate(settings);

        // assert
        results.Should().Contain(r => r.MemberNames.Contains(nameof(JWTSettings.RefreshTokenExpiryInDays)));
    }

    [Fact]
    public void JWTSettings_ActiveKeyId_DefaultsToAuto()
    {
        // arrange / act — the "auto" sentinel means "pick first key in the directory."
        // Single-key dev setups rely on this default.
        var settings = new JWTSettings();

        // assert
        settings.ActiveKeyId.Should().Be("auto");
    }

    // ─── IdentitySettings (nested) ──────────────────────────────────────────────────────

    [Fact]
    public void PasswordSettings_Defaults_MatchNistGuidance()
    {
        // arrange / act — defaults should equal NIST 800-63B / OWASP guidance: 12-char min,
        // require digit/upper/lower/symbol. A regression that loosens the defaults silently
        // weakens every deployment that doesn't explicitly override them.
        var settings = new PasswordSettings();

        // assert
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
        // arrange — Range(1, 256). 0 or negative would disable length validation;
        // > 256 is unenforceable in practice (Identity hashes the password).
        var settings = new PasswordSettings { RequiredLength = length };

        // act
        var results = Validate(settings);

        // assert
        results.Should().Contain(r => r.MemberNames.Contains(nameof(PasswordSettings.RequiredLength)));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(257)]
    public void PasswordSettings_RequiredUniqueCharsOutOfRange_Fails(int chars)
    {
        // arrange — Range(1, 256).
        var settings = new PasswordSettings { RequiredUniqueChars = chars };

        // act
        var results = Validate(settings);

        // assert
        results.Should().Contain(r => r.MemberNames.Contains(nameof(PasswordSettings.RequiredUniqueChars)));
    }

    [Fact]
    public void UserSettings_Defaults_RequireUniqueEmailAndPermissiveCharacterSet()
    {
        // arrange / act
        var settings = new UserSettings();

        // assert — RequireUniqueEmail defaults true: the password-reset flow looks up by
        // email, so non-unique emails would break it. The default char set matches
        // Identity's own default (alphanumeric + -._@+).
        settings.RequireUniqueEmail.Should().BeTrue();
        settings.AllowedUserNameCharacters
            .Should().Be("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._@+");
        settings.ReservedUserNames.Should().NotBeEmpty(because: "platform reserves admin-adjacent names.");
    }

    [Fact]
    public void LockoutSettings_Defaults_AllowedForNewUsersAndAggressive()
    {
        // arrange / act
        var settings = new LockoutSettings();

        // assert — defaults are the security baseline: lockout on by default, 3 attempts,
        // 2 minutes. Loosening any of these without thinking about it weakens the
        // brute-force defence.
        settings.AllowedForNewUsers.Should().BeTrue();
        settings.DefaultLockoutDurationInMinutes.Should().Be(2);
        settings.MaxFailedAccessAttempts.Should().Be(3);
    }

    [Theory]
    [InlineData(0.05)]
    [InlineData(1441)]
    public void LockoutSettings_DefaultLockoutDurationOutOfRange_Fails(double minutes)
    {
        // arrange — Range(0.1, 1440).
        var settings = new LockoutSettings { DefaultLockoutDurationInMinutes = minutes };

        // act
        var results = Validate(settings);

        // assert
        results.Should().Contain(r => r.MemberNames.Contains(nameof(LockoutSettings.DefaultLockoutDurationInMinutes)));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(101)]
    public void LockoutSettings_MaxFailedAccessAttemptsOutOfRange_Fails(int attempts)
    {
        // arrange — Range(1, 100). NIST-recommended ceiling is 100.
        var settings = new LockoutSettings { MaxFailedAccessAttempts = attempts };

        // act
        var results = Validate(settings);

        // assert
        results.Should().Contain(r => r.MemberNames.Contains(nameof(LockoutSettings.MaxFailedAccessAttempts)));
    }

    // ─── AdminAccountSeedSettings ───────────────────────────────────────────────────────

    [Fact]
    public void AdminAccountSeedSettings_FullyPopulated_Passes()
    {
        // arrange
        var settings = new AdminAccountSeedSettings
        {
            Email = "admin@example.com",
            Password = "AdminPass!1234",
            FirstName = "Admin",
        };

        // act / assert
        Validate(settings).Should().BeEmpty();
    }

    [Theory]
    [InlineData(nameof(AdminAccountSeedSettings.Email))]
    [InlineData(nameof(AdminAccountSeedSettings.Password))]
    [InlineData(nameof(AdminAccountSeedSettings.FirstName))]
    public void AdminAccountSeedSettings_RequiredFieldMissing_Fails(string field)
    {
        // arrange — every Required field individually.
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

        // act
        var results = Validate(settings);

        // assert
        results.Should().Contain(r => r.MemberNames.Contains(field));
    }

    [Fact]
    public void AdminAccountSeedSettings_InvalidEmail_Fails()
    {
        // arrange — EmailAddress catches obvious garbage.
        var settings = new AdminAccountSeedSettings { Email = "not-email", Password = "p", FirstName = "A" };

        // act
        var results = Validate(settings);

        // assert
        results.Should().Contain(r => r.MemberNames.Contains(nameof(AdminAccountSeedSettings.Email)));
    }

    [Theory]
    [InlineData(nameof(AdminAccountSeedSettings.FirstName), 51)]
    [InlineData(nameof(AdminAccountSeedSettings.LastName), 51)]
    [InlineData(nameof(AdminAccountSeedSettings.Country), 61)]
    public void AdminAccountSeedSettings_LengthBoundedFieldOverLength_Fails(string field, int overLength)
    {
        // arrange — column-bound caps mirrored on the seed settings.
        var oversize = new string('x', overLength);
        var settings = new AdminAccountSeedSettings { Email = "a@b.com", Password = "p", FirstName = "A" };
        switch (field)
        {
            case nameof(AdminAccountSeedSettings.FirstName): settings.FirstName = oversize; break;
            case nameof(AdminAccountSeedSettings.LastName): settings.LastName = oversize; break;
            case nameof(AdminAccountSeedSettings.Country): settings.Country = oversize; break;
        }

        // act
        var results = Validate(settings);

        // assert
        results.Should().Contain(r => r.MemberNames.Contains(field));
    }

    [Fact]
    public void AdminAccountSeedSettings_PhoneNumberMalformed_Fails()
    {
        // arrange — [Phone] catches obvious garbage in the optional phone field.
        var settings = new AdminAccountSeedSettings
        {
            Email = "a@b.com",
            Password = "p",
            FirstName = "A",
            PhoneNumber = "obviously-not-a-phone",
        };

        // act
        var results = Validate(settings);

        // assert
        results.Should().Contain(r => r.MemberNames.Contains(nameof(AdminAccountSeedSettings.PhoneNumber)));
    }

    // ─── HostingSettings ────────────────────────────────────────────────────────────────

    [Fact]
    public void HostingSettings_Defaults_BackgroundWorkersOnAndOneMbBodyCap()
    {
        // arrange / act
        var settings = new HostingSettings();

        // assert — defaults preserve single-replica deployments (workers on) and pin a
        // 1 MB request body cap (well above what auth endpoints need, well below
        // Kestrel's 30 MB default DoS-surface).
        settings.BackgroundWorkersEnabled.Should().BeTrue();
        settings.MaxRequestBodySizeInKilobytes.Should().Be(1024);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(-1)]
    [InlineData(30_721)]
    public void HostingSettings_MaxRequestBodySizeInKilobytesOutOfRange_Fails(int kb)
    {
        // arrange — Range(1, 30_720). Below 1 KB blocks normal login bodies; above
        // 30 MB matches Kestrel's own default and the cap stops doing anything useful.
        var settings = new HostingSettings { MaxRequestBodySizeInKilobytes = kb };

        // act
        var results = Validate(settings);

        // assert
        results.Should().Contain(r => r.MemberNames.Contains(nameof(HostingSettings.MaxRequestBodySizeInKilobytes)));
    }

    // ─── ThresholdEscalationSettings (defaults — no annotations) ────────────────────────

    [Fact]
    public void ThresholdEscalationSettings_Defaults_AggressiveButForgiving()
    {
        // arrange / act
        var settings = new ThresholdEscalationSettings();

        // assert — defaults: enabled, 1-min sweep, 5-min window, warn at 2, lock at 5.
        // Intentionally aggressive because well-behaved clients don't replay revoked
        // tokens; anything beyond a couple of replays is buggy or hostile.
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
        // arrange / act
        var settings = new DataRetentionSettings();

        // assert — defaults: cleanup runs twice a day, audit retention 90 days.
        // Specific values are operator-tunable but defaults are documented.
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
