﻿using System.ComponentModel.DataAnnotations;

namespace Skuzzle.Core.Service.AuthenticationService.Settings;

public class JwtSettings
{
    [Required]
    [MinLength(64)]
    public required string Key { get; set; }

    [Required]
    public required string Issuer { get; set; }

    [Required]
    public required string Audience { get; set; }
}