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
    /// Stamped at object construction time and persisted on the first SaveChanges. Pinned
    /// here on the entity (rather than via a DB-side <c>DEFAULT</c>) so the model stays
    /// provider-agnostic — SQLite-backed unit tests, MySQL-backed integration tests, and
    /// production all see the same shape.
    ///
    /// <para>The corresponding migration adds the column with a MySQL <c>DEFAULT
    /// (UTC_TIMESTAMP(6))</c> for backfilling existing rows at migrate time. That default
    /// only matters during the migration itself — every subsequent INSERT carries this
    /// initializer's value because EF always sends a non-default property in the INSERT.</para>
    /// </summary>
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
}
