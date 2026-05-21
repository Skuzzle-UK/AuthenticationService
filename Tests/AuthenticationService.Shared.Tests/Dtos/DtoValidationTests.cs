using System.ComponentModel.DataAnnotations;
using AuthenticationService.Shared.Dtos;
using AuthenticationService.Shared.Enums;
using AwesomeAssertions;

namespace AuthenticationService.Shared.Tests.Dtos;

/// <summary>
/// Pins DataAnnotation constraints on every input DTO. [ApiController]'s automatic
/// ModelState short-circuit runs these on the body; a silently-disappearing constraint
/// would let bad payloads reach the controller / database.
/// </summary>
public class DtoValidationTests
{
    // ─── RegistrationDto ────────────────────────────────────────────────────────────────

    [Fact]
    public void RegistrationDto_FullyPopulated_PassesValidation()
    {
        var dto = new RegistrationDto
        {
            UserName = "alice",
            FirstName = "Alice",
            LastName = "Smith",
            DateOfBirth = new DateOnly(1990, 1, 1),
            Email = "alice@example.com",
            PhoneNumber = "+44 1234 567890",
            Country = "UK",
            Password = "Sup3rSecure!Pa$$",
            ConfirmPassword = "Sup3rSecure!Pa$$",
            PreferredMfaProvider = MfaProviders.Email,
        };

        var results = Validate(dto);

        results.Should().BeEmpty();
    }

    [Theory]
    [InlineData(nameof(RegistrationDto.UserName), "UserName is required.")]
    [InlineData(nameof(RegistrationDto.DateOfBirth), "Date of birth is required.")]
    [InlineData(nameof(RegistrationDto.Email), "Email is required.")]
    [InlineData(nameof(RegistrationDto.Password), "Password is required.")]
    public void RegistrationDto_RequiredFieldMissing_ProducesFieldNamedError(string field, string expectedMessage)
    {
        var dto = MinimalValidRegistrationDto();
        switch (field)
        {
            case nameof(RegistrationDto.UserName): dto.UserName = null; break;
            case nameof(RegistrationDto.DateOfBirth): dto.DateOfBirth = null; break;
            case nameof(RegistrationDto.Email): dto.Email = null; break;
            case nameof(RegistrationDto.Password): dto.Password = null; break;
        }

        var results = Validate(dto);

        // Exact-message assertion: operators read this in the API response and act on it.
        results.Should().ContainSingle(r => r.MemberNames.Contains(field) && r.ErrorMessage == expectedMessage);
    }

    [Fact]
    public void RegistrationDto_ConfirmPasswordMismatch_ProducesCompareError()
    {
        var dto = MinimalValidRegistrationDto();
        dto.Password = "MatchMe123!";
        dto.ConfirmPassword = "Different!";

        var results = Validate(dto);

        results.Should().Contain(r =>
            r.MemberNames.Contains(nameof(RegistrationDto.ConfirmPassword))
            && r.ErrorMessage == "The password and confirmation password do not match.");
    }

    [Fact]
    public void RegistrationDto_EmailMalformed_ProducesEmailAddressError()
    {
        var dto = MinimalValidRegistrationDto();
        dto.Email = "not-an-email";

        var results = Validate(dto);

        results.Should().Contain(r => r.MemberNames.Contains(nameof(RegistrationDto.Email)));
    }

    [Theory]
    [InlineData(nameof(RegistrationDto.UserName), 51)]
    [InlineData(nameof(RegistrationDto.FirstName), 51)]
    [InlineData(nameof(RegistrationDto.LastName), 51)]
    [InlineData(nameof(RegistrationDto.Country), 61)]
    [InlineData(nameof(RegistrationDto.AddressLine1), 257)]
    [InlineData(nameof(RegistrationDto.AddressLine2), 257)]
    [InlineData(nameof(RegistrationDto.AddressLine3), 257)]
    [InlineData(nameof(RegistrationDto.Postcode), 21)]
    [InlineData(nameof(RegistrationDto.City), 61)]
    public void RegistrationDto_LengthBoundedField_OverLengthFails(string field, int overLength)
    {
        var dto = MinimalValidRegistrationDto();
        var oversize = new string('x', overLength);
        switch (field)
        {
            case nameof(RegistrationDto.UserName): dto.UserName = oversize; break;
            case nameof(RegistrationDto.FirstName): dto.FirstName = oversize; break;
            case nameof(RegistrationDto.LastName): dto.LastName = oversize; break;
            case nameof(RegistrationDto.Country): dto.Country = oversize; break;
            case nameof(RegistrationDto.AddressLine1): dto.AddressLine1 = oversize; break;
            case nameof(RegistrationDto.AddressLine2): dto.AddressLine2 = oversize; break;
            case nameof(RegistrationDto.AddressLine3): dto.AddressLine3 = oversize; break;
            case nameof(RegistrationDto.Postcode): dto.Postcode = oversize; break;
            case nameof(RegistrationDto.City): dto.City = oversize; break;
        }

        var results = Validate(dto);

        results.Should().Contain(r => r.MemberNames.Contains(field));
    }

    [Fact]
    public void RegistrationDto_PhoneNumberMalformed_FailsPhoneValidation()
    {
        var dto = MinimalValidRegistrationDto();
        dto.PhoneNumber = "not a phone";

        var results = Validate(dto);

        results.Should().Contain(r => r.MemberNames.Contains(nameof(RegistrationDto.PhoneNumber)));
    }

    // ─── UpdateProfileDto ───────────────────────────────────────────────────────────────

    [Fact]
    public void UpdateProfileDto_EmptyBody_PassesBecauseEveryFieldOptional()
    {
        // PUT /me with an empty body means "don't change anything" — the controller
        // skips writes. A [Required] sneaking in here would break that contract.
        var dto = new UpdateProfileDto();

        var results = Validate(dto);

        results.Should().BeEmpty();
    }

    [Theory]
    [InlineData(nameof(UpdateProfileDto.FirstName), 51)]
    [InlineData(nameof(UpdateProfileDto.LastName), 51)]
    [InlineData(nameof(UpdateProfileDto.Country), 61)]
    [InlineData(nameof(UpdateProfileDto.AddressLine1), 257)]
    [InlineData(nameof(UpdateProfileDto.AddressLine2), 257)]
    [InlineData(nameof(UpdateProfileDto.AddressLine3), 257)]
    [InlineData(nameof(UpdateProfileDto.City), 61)]
    [InlineData(nameof(UpdateProfileDto.Postcode), 21)]
    public void UpdateProfileDto_LengthBoundedField_OverLengthFails(string field, int overLength)
    {
        var dto = new UpdateProfileDto();
        var oversize = new string('x', overLength);
        switch (field)
        {
            case nameof(UpdateProfileDto.FirstName): dto.FirstName = oversize; break;
            case nameof(UpdateProfileDto.LastName): dto.LastName = oversize; break;
            case nameof(UpdateProfileDto.Country): dto.Country = oversize; break;
            case nameof(UpdateProfileDto.AddressLine1): dto.AddressLine1 = oversize; break;
            case nameof(UpdateProfileDto.AddressLine2): dto.AddressLine2 = oversize; break;
            case nameof(UpdateProfileDto.AddressLine3): dto.AddressLine3 = oversize; break;
            case nameof(UpdateProfileDto.City): dto.City = oversize; break;
            case nameof(UpdateProfileDto.Postcode): dto.Postcode = oversize; break;
        }

        var results = Validate(dto);

        results.Should().Contain(r => r.MemberNames.Contains(field));
    }

    [Fact]
    public void UpdateProfileDto_PhoneNumberMalformed_FailsPhoneValidation()
    {
        // UpdateProfile resets PhoneNumberConfirmed when phone changes — accepting
        // garbage would corrupt the SMS-MFA path.
        var dto = new UpdateProfileDto { PhoneNumber = "not a phone" };

        var results = Validate(dto);

        results.Should().Contain(r => r.MemberNames.Contains(nameof(UpdateProfileDto.PhoneNumber)));
    }

    // ─── ChangePasswordDto ──────────────────────────────────────────────────────────────

    [Fact]
    public void ChangePasswordDto_BothPasswordsAndMatchingConfirm_Passes()
    {
        var dto = new ChangePasswordDto
        {
            OldPassword = "old",
            NewPassword = "newPass!1234",
            ConfirmPassword = "newPass!1234",
        };

        Validate(dto).Should().BeEmpty();
    }

    [Theory]
    [InlineData(nameof(ChangePasswordDto.OldPassword), "Old password is required.")]
    [InlineData(nameof(ChangePasswordDto.NewPassword), "New password is required.")]
    public void ChangePasswordDto_MissingPasswords_FailsWithExpectedMessage(string field, string expectedMessage)
    {
        var dto = new ChangePasswordDto
        {
            OldPassword = "old",
            NewPassword = "newPass!",
            ConfirmPassword = "newPass!",
        };
        if (field == nameof(ChangePasswordDto.OldPassword)) dto.OldPassword = null;
        else dto.NewPassword = null;

        var results = Validate(dto);

        results.Should().Contain(r => r.MemberNames.Contains(field) && r.ErrorMessage == expectedMessage);
    }

    [Fact]
    public void ChangePasswordDto_ConfirmPasswordMismatch_FailsCompareValidation()
    {
        var dto = new ChangePasswordDto
        {
            OldPassword = "old",
            NewPassword = "newPass!",
            ConfirmPassword = "different!",
        };

        var results = Validate(dto);

        results.Should().Contain(r => r.MemberNames.Contains(nameof(ChangePasswordDto.ConfirmPassword)));
    }

    // ─── ResetForgottenPasswordDto ──────────────────────────────────────────────────────

    [Fact]
    public void ResetForgottenPasswordDto_Populated_Passes()
    {
        var dto = new ResetForgottenPasswordDto
        {
            Email = "x@example.com",
            Token = "reset-token",
            NewPassword = "newpass!",
            ConfirmPassword = "newpass!",
        };
        Validate(dto).Should().BeEmpty();
    }

    [Fact]
    public void ResetForgottenPasswordDto_MismatchedConfirm_Fails()
    {
        var dto = new ResetForgottenPasswordDto
        {
            Email = "x@example.com",
            Token = "tok",
            NewPassword = "newpass!",
            ConfirmPassword = "differs!",
        };

        var results = Validate(dto);

        results.Should().Contain(r => r.MemberNames.Contains(nameof(ResetForgottenPasswordDto.ConfirmPassword)));
    }

    // ─── AuthenticationDto ──────────────────────────────────────────────────────────────

    [Fact]
    public void AuthenticationDto_FullyPopulated_Passes()
    {
        var dto = new AuthenticationDto { Email = "u@example.com", Password = "p" };
        Validate(dto).Should().BeEmpty();
    }

    [Theory]
    [InlineData(nameof(AuthenticationDto.Email), "Email is required.")]
    [InlineData(nameof(AuthenticationDto.Password), "Password is required.")]
    public void AuthenticationDto_RequiredFieldMissing_FailsWithExpectedMessage(string field, string expected)
    {
        var dto = new AuthenticationDto { Email = "u@example.com", Password = "p" };
        if (field == nameof(AuthenticationDto.Email)) dto.Email = null;
        else dto.Password = null;

        var results = Validate(dto);

        results.Should().Contain(r => r.MemberNames.Contains(field) && r.ErrorMessage == expected);
    }

    // ─── MfaAuthenticationDto ───────────────────────────────────────────────────────────

    [Fact]
    public void MfaAuthenticationDto_FullyPopulated_Passes()
    {
        var dto = new MfaAuthenticationDto { Email = "u@example.com", MfaProvider = MfaProviders.Email, Token = "123456" };
        Validate(dto).Should().BeEmpty();
    }

    [Theory]
    [InlineData(nameof(MfaAuthenticationDto.Email), "Email is required.")]
    [InlineData(nameof(MfaAuthenticationDto.MfaProvider), "MfaProvider is required.")]
    [InlineData(nameof(MfaAuthenticationDto.Token), "Token is required.")]
    public void MfaAuthenticationDto_RequiredFieldMissing_FailsWithExpectedMessage(string field, string expected)
    {
        var dto = new MfaAuthenticationDto { Email = "u@example.com", MfaProvider = MfaProviders.Email, Token = "123456" };
        switch (field)
        {
            case nameof(MfaAuthenticationDto.Email): dto.Email = null; break;
            case nameof(MfaAuthenticationDto.MfaProvider): dto.MfaProvider = null; break;
            case nameof(MfaAuthenticationDto.Token): dto.Token = null; break;
        }

        var results = Validate(dto);

        results.Should().Contain(r => r.MemberNames.Contains(field) && r.ErrorMessage == expected);
    }

    // ─── ForgotPasswordDto ──────────────────────────────────────────────────────────────

    [Fact]
    public void ForgotPasswordDto_WithEmail_Passes()
    {
        Validate(new ForgotPasswordDto { Email = "u@example.com" }).Should().BeEmpty();
    }

    [Fact]
    public void ForgotPasswordDto_MissingEmail_Fails()
    {
        var dto = new ForgotPasswordDto();

        var results = Validate(dto);

        results.Should().Contain(r => r.MemberNames.Contains(nameof(ForgotPasswordDto.Email)));
    }

    // ─── LockAccountDto ─────────────────────────────────────────────────────────────────

    [Fact]
    public void LockAccountDto_FullyPopulated_Passes()
    {
        Validate(new LockAccountDto { Email = "u@example.com", Token = "lock-token" }).Should().BeEmpty();
    }

    [Theory]
    [InlineData(nameof(LockAccountDto.Email), "Email is required.")]
    [InlineData(nameof(LockAccountDto.Token), "Token is required.")]
    public void LockAccountDto_RequiredFieldMissing_FailsWithExpectedMessage(string field, string expected)
    {
        var dto = new LockAccountDto { Email = "u@example.com", Token = "tok" };
        if (field == nameof(LockAccountDto.Email)) dto.Email = null;
        else dto.Token = null;

        var results = Validate(dto);

        results.Should().Contain(r => r.MemberNames.Contains(field) && r.ErrorMessage == expected);
    }

    // ─── RefreshTokenDto ────────────────────────────────────────────────────────────────

    [Fact]
    public void RefreshTokenDto_WithToken_Passes()
    {
        Validate(new RefreshTokenDto { RefreshToken = "rt" }).Should().BeEmpty();
    }

    [Fact]
    public void RefreshTokenDto_MissingToken_Fails()
    {
        var dto = new RefreshTokenDto();

        var results = Validate(dto);

        results.Should().Contain(r =>
            r.MemberNames.Contains(nameof(RefreshTokenDto.RefreshToken))
            && r.ErrorMessage == "RefreshToken is required.");
    }

    // ─── ResendEmailConfirmationDto + EnableMfaRequest ─────────────────────────────────

    /// <summary>
    /// These two are annotation-free today — kept as no-op shape pinning so a future
    /// [Required] sneaking in without updating the controller's null-checks is caught.
    /// </summary>
    [Fact]
    public void ResendEmailConfirmationDto_DefaultInstance_PassesValidation()
    {
        Validate(new ResendEmailConfirmationDto()).Should().BeEmpty();
    }

    [Fact]
    public void EnableMfaRequest_DefaultInstance_PassesValidation()
    {
        Validate(new EnableMfaRequest()).Should().BeEmpty();
    }

    // ─── helpers ────────────────────────────────────────────────────────────────────────

    private static List<ValidationResult> Validate(object instance)
    {
        var results = new List<ValidationResult>();
        Validator.TryValidateObject(instance, new ValidationContext(instance), results, validateAllProperties: true);
        return results;
    }

    private static RegistrationDto MinimalValidRegistrationDto() => new()
    {
        UserName = "alice",
        DateOfBirth = new DateOnly(1990, 1, 1),
        Email = "alice@example.com",
        Password = "P@ssw0rd1234",
    };
}
