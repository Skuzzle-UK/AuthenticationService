﻿using System.ComponentModel.DataAnnotations;

namespace AuthenticationService.Shared.Dtos;

public class RecoverAccountDto
{
    [Required(ErrorMessage = "UserName is required.")]
    public string? UserName { get; set; }

    public string? FirstName { get; set; }

    public string? LastName { get; set; }

    public DateOnly? DateOfBirth { get; set; }

    [Required(ErrorMessage = "Email is required."), EmailAddress]
    public string? Email { get; set; }

    [Phone]
    public string? PhoneNumber { get; set; }

    public string? Country { get; set; }

    public string? MothersMaidenName { get; set; }

    public string? AddressLine1 { get; set; }

    public string? AddressLine2 { get; set; }

    public string? AddressLine3 { get; set; }

    public string? Postcode { get; set; }

    public string? City { get; set; }

    [Required(ErrorMessage = "NewPassword is required.")]
    public string? NewPassword { get; set; }

    [Compare("NewPassword", ErrorMessage = "The password and confirmation password do not match.")]
    public string? ConfirmPassword { get; set; }

    public string? LockAccountUri { get; set; }
}
