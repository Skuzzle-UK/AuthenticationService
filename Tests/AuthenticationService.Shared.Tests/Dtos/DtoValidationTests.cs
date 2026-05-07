using System.ComponentModel.DataAnnotations;
using AuthenticationService.Shared.Dtos;
using AuthenticationService.Shared.Enums;
using AwesomeAssertions;

namespace AuthenticationService.Shared.Tests.Dtos;

/// <summary>
/// <para>Every input DTO accepted by an API endpoint relies on <c>[ApiController]</c>'s
/// automatic ModelState short-circuit, which runs DataAnnotation validation on the body.
/// If any of the constraints below silently disappear, the endpoint accepts payloads it
/// shouldn't and the controller hits null/over-length values that propagate into the
/// database. These tests pin every annotation by exercising both the success path
/// (fully-populated DTO validates) and the obvious failure paths (each constraint that
/// has documented intent).</para>
///
/// <para>DTOs covered:
/// <see cref="RegistrationDto"/>, <see cref="UpdateProfileDto"/>, <see cref="ChangePasswordDto"/>,
/// <see cref="ResetForgottenPasswordDto"/>, <see cref="AuthenticationDto"/> (no annotations
/// today — included for shape pinning), <see cref="MfaAuthenticationDto"/>,
/// <see cref="ForgotPasswordDto"/>, <see cref="LockAccountDto"/>,
/// <see cref="ResendEmailConfirmationDto"/>, <see cref="EnableMfaRequest"/>,
/// <see cref="RefreshTokenDto"/>.</para>
/// </summary>
public class DtoValidationTests
{
    // ─── RegistrationDto ────────────────────────────────────────────────────────────────

    [Fact]
    public void RegistrationDto_FullyPopulated_PassesValidation()
    {
        // arrange — every required field present, every length-bounded field within bounds.
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

        // act
        var results = Validate(dto);

        // assert
        results.Should().BeEmpty();
    }

    [Theory]
    [InlineData(nameof(RegistrationDto.UserName), "UserName is required.")]
    [InlineData(nameof(RegistrationDto.DateOfBirth), "Date of birth is required.")]
    [InlineData(nameof(RegistrationDto.Email), "Email is required.")]
    [InlineData(nameof(RegistrationDto.Password), "Password is required.")]
    public void RegistrationDto_RequiredFieldMissing_ProducesFieldNamedError(string field, string expectedMessage)
    {
        // arrange — start fully-populated, null one [Required] field at a time.
        var dto = MinimalValidRegistrationDto();
        switch (field)
        {
            case nameof(RegistrationDto.UserName): dto.UserName = null; break;
            case nameof(RegistrationDto.DateOfBirth): dto.DateOfBirth = null; break;
            case nameof(RegistrationDto.Email): dto.Email = null; break;
            case nameof(RegistrationDto.Password): dto.Password = null; break;
        }

        // act
        var results = Validate(dto);

        // assert — the operator-facing error message must be exactly the documented one,
        // because operators read the error in the API response and act on it.
        results.Should().ContainSingle(r => r.MemberNames.Contains(field) && r.ErrorMessage == expectedMessage);
    }

    [Fact]
    public void RegistrationDto_ConfirmPasswordMismatch_ProducesCompareError()
    {
        // arrange — Compare attribute means "ConfirmPassword must equal Password".
        var dto = MinimalValidRegistrationDto();
        dto.Password = "MatchMe123!";
        dto.ConfirmPassword = "Different!";

        // act
        var results = Validate(dto);

        // assert
        results.Should().Contain(r =>
            r.MemberNames.Contains(nameof(RegistrationDto.ConfirmPassword))
            && r.ErrorMessage == "The password and confirmation password do not match.");
    }

    [Fact]
    public void RegistrationDto_EmailMalformed_ProducesEmailAddressError()
    {
        // arrange — bypass DataAnnotation Email format. The endpoint is the perimeter for
        // garbage input; if [EmailAddress] regression-fails, garbage flows to UserManager.
        var dto = MinimalValidRegistrationDto();
        dto.Email = "not-an-email";

        // act
        var results = Validate(dto);

        // assert
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
        // arrange — pin every MaxLength bound so a future loosening of a column-mapped
        // limit can't slip in undetected.
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

        // act
        var results = Validate(dto);

        // assert
        results.Should().Contain(r => r.MemberNames.Contains(field));
    }

    [Fact]
    public void RegistrationDto_PhoneNumberMalformed_FailsPhoneValidation()
    {
        // arrange — [Phone] catches obviously-not-a-phone values. Strict format rules are
        // up to the carrier; this just gates the obvious garbage.
        var dto = MinimalValidRegistrationDto();
        dto.PhoneNumber = "not a phone";

        // act
        var results = Validate(dto);

        // assert
        results.Should().Contain(r => r.MemberNames.Contains(nameof(RegistrationDto.PhoneNumber)));
    }

    // ─── UpdateProfileDto ───────────────────────────────────────────────────────────────

    [Fact]
    public void UpdateProfileDto_EmptyBody_PassesBecauseEveryFieldOptional()
    {
        // arrange — PUT /me with an empty body is valid (means "don't change anything").
        // The controller skips writes when nothing changed. If a [Required] sneaks in here
        // it would break that contract.
        var dto = new UpdateProfileDto();

        // act
        var results = Validate(dto);

        // assert
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
        // arrange — same column-bound caps as the entity, mirrored in the DTO so the
        // perimeter rejects oversized values before they hit the DB.
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

        // act
        var results = Validate(dto);

        // assert
        results.Should().Contain(r => r.MemberNames.Contains(field));
    }

    [Fact]
    public void UpdateProfileDto_PhoneNumberMalformed_FailsPhoneValidation()
    {
        // arrange — same rationale as RegistrationDto. UpdateProfile resets PhoneNumberConfirmed
        // when phone changes — accepting garbage would corrupt the SMS-MFA path.
        var dto = new UpdateProfileDto { PhoneNumber = "not a phone" };

        // act
        var results = Validate(dto);

        // assert
        results.Should().Contain(r => r.MemberNames.Contains(nameof(UpdateProfileDto.PhoneNumber)));
    }

    // ─── ChangePasswordDto ──────────────────────────────────────────────────────────────

    [Fact]
    public void ChangePasswordDto_BothPasswordsAndMatchingConfirm_Passes()
    {
        // arrange / act
        var dto = new ChangePasswordDto
        {
            OldPassword = "old",
            NewPassword = "newPass!1234",
            ConfirmPassword = "newPass!1234",
        };

        // assert
        Validate(dto).Should().BeEmpty();
    }

    [Theory]
    [InlineData(nameof(ChangePasswordDto.OldPassword), "Old password is required.")]
    [InlineData(nameof(ChangePasswordDto.NewPassword), "New password is required.")]
    public void ChangePasswordDto_MissingPasswords_FailsWithExpectedMessage(string field, string expectedMessage)
    {
        // arrange — both password fields are [Required]. Either missing must fail with the
        // documented operator-facing message.
        var dto = new ChangePasswordDto
        {
            OldPassword = "old",
            NewPassword = "newPass!",
            ConfirmPassword = "newPass!",
        };
        if (field == nameof(ChangePasswordDto.OldPassword)) dto.OldPassword = null;
        else dto.NewPassword = null;

        // act
        var results = Validate(dto);

        // assert
        results.Should().Contain(r => r.MemberNames.Contains(field) && r.ErrorMessage == expectedMessage);
    }

    [Fact]
    public void ChangePasswordDto_ConfirmPasswordMismatch_FailsCompareValidation()
    {
        // arrange — same Compare("NewPassword") shape as registration.
        var dto = new ChangePasswordDto
        {
            OldPassword = "old",
            NewPassword = "newPass!",
            ConfirmPassword = "different!",
        };

        // act
        var results = Validate(dto);

        // assert
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
        // arrange — Compare gates the reset endpoint just like change-password.
        var dto = new ResetForgottenPasswordDto
        {
            Email = "x@example.com",
            Token = "tok",
            NewPassword = "newpass!",
            ConfirmPassword = "differs!",
        };

        // act
        var results = Validate(dto);

        // assert
        results.Should().Contain(r => r.MemberNames.Contains(nameof(ResetForgottenPasswordDto.ConfirmPassword)));
    }

    // ─── AuthenticationDto ──────────────────────────────────────────────────────────────

    [Fact]
    public void AuthenticationDto_FullyPopulated_Passes()
    {
        // arrange / act
        var dto = new AuthenticationDto { Email = "u@example.com", Password = "p" };
        // assert
        Validate(dto).Should().BeEmpty();
    }

    [Theory]
    [InlineData(nameof(AuthenticationDto.Email), "Email is required.")]
    [InlineData(nameof(AuthenticationDto.Password), "Password is required.")]
    public void AuthenticationDto_RequiredFieldMissing_FailsWithExpectedMessage(string field, string expected)
    {
        // arrange — login DTO must reject empty email/password at the perimeter, before
        // they hit UserManager (which would otherwise produce a less helpful error).
        var dto = new AuthenticationDto { Email = "u@example.com", Password = "p" };
        if (field == nameof(AuthenticationDto.Email)) dto.Email = null;
        else dto.Password = null;

        // act
        var results = Validate(dto);

        // assert
        results.Should().Contain(r => r.MemberNames.Contains(field) && r.ErrorMessage == expected);
    }

    // ─── MfaAuthenticationDto ───────────────────────────────────────────────────────────

    [Fact]
    public void MfaAuthenticationDto_FullyPopulated_Passes()
    {
        // arrange / act
        var dto = new MfaAuthenticationDto { Email = "u@example.com", MfaProvider = MfaProviders.Email, Token = "123456" };
        // assert
        Validate(dto).Should().BeEmpty();
    }

    [Theory]
    [InlineData(nameof(MfaAuthenticationDto.Email), "Email is required.")]
    [InlineData(nameof(MfaAuthenticationDto.MfaProvider), "MfaProvider is required.")]
    [InlineData(nameof(MfaAuthenticationDto.Token), "Token is required.")]
    public void MfaAuthenticationDto_RequiredFieldMissing_FailsWithExpectedMessage(string field, string expected)
    {
        // arrange — MFA endpoint can't act on a missing email (no user to look up),
        // missing provider (don't know which token type to verify), or missing token.
        var dto = new MfaAuthenticationDto { Email = "u@example.com", MfaProvider = MfaProviders.Email, Token = "123456" };
        switch (field)
        {
            case nameof(MfaAuthenticationDto.Email): dto.Email = null; break;
            case nameof(MfaAuthenticationDto.MfaProvider): dto.MfaProvider = null; break;
            case nameof(MfaAuthenticationDto.Token): dto.Token = null; break;
        }

        // act
        var results = Validate(dto);

        // assert
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
        // arrange — without email there's no user to send the reset link to.
        var dto = new ForgotPasswordDto();

        // act
        var results = Validate(dto);

        // assert
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
        // arrange — panic-button lock endpoint needs to know who (Email) and prove the
        // request is genuine via the one-time Token from the password-changed email.
        var dto = new LockAccountDto { Email = "u@example.com", Token = "tok" };
        if (field == nameof(LockAccountDto.Email)) dto.Email = null;
        else dto.Token = null;

        // act
        var results = Validate(dto);

        // assert
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
        // arrange — refresh endpoint can't do anything without the refresh token. The
        // expired access token also has to be supplied (it's in the Authorization header),
        // but this DTO is just the body shape so it only enforces the body field.
        var dto = new RefreshTokenDto();

        // act
        var results = Validate(dto);

        // assert
        results.Should().Contain(r =>
            r.MemberNames.Contains(nameof(RefreshTokenDto.RefreshToken))
            && r.ErrorMessage == "RefreshToken is required.");
    }

    // ─── ResendEmailConfirmationDto + EnableMfaRequest ─────────────────────────────────

    /// <summary>
    /// These two are genuinely annotation-free today. Kept as no-op shape pinning so a
    /// future Required snuck in without updating the controller's defensive null-checks
    /// would still be caught here.
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
