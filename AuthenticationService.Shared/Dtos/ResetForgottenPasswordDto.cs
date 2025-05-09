﻿using System.ComponentModel.DataAnnotations;

namespace AuthenticationService.Shared.Dtos;

public class ResetForgottenPasswordDto
{
    [Required(ErrorMessage = "Email is required."), EmailAddress]
    public string? Email { get; set; }

    [Required(ErrorMessage = "Token is required.")]
    public string? Token { get; set; }

    [Required(ErrorMessage = "New password is required.")]
    public string? NewPassword { get; set; }

    [Compare("NewPassword", ErrorMessage = "The password and confirmation password do not match.")]
    public string? ConfirmPassword { get; set; }

    public string? LockAccountUri { get; set; }
}
