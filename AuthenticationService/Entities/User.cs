using AuthenticationService.Shared.Enums;
using Microsoft.AspNetCore.Identity;
using System.ComponentModel.DataAnnotations;

namespace AuthenticationService.Entities;

public class User : IdentityUser
{
    [MaxLength(50)]
    public string? FirstName { get; set; }

    [MaxLength(50)]
    public string? LastName { get; set; }

    public DateOnly? DateOfBirth { get; set; }

    [MaxLength(60)]
    public string? Country { get; set; }

    public MfaProviders PreferredMfaProvider { get; set; }

    [MaxLength(256)]
    public string? AddressLine1 { get; set; }

    [MaxLength(256)]
    public string? AddressLine2 { get; set; }

    [MaxLength(256)]
    public string? AddressLine3 { get; set; }

    [MaxLength(20)]
    public string? Postcode { get; set; }

    [MaxLength(60)]
    public string? City { get; set; }

    /// <summary>
    /// Stamped at construction. Initializer (not DB DEFAULT) keeps the model
    /// provider-agnostic across SQLite tests and MySQL prod. The migration adds a MySQL
    /// DEFAULT only for backfilling existing rows.
    /// </summary>
    public DateTimeOffset CreatedAt { get; set; } = DateTimeOffset.UtcNow;
}
