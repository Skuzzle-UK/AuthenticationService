using AuthenticationService.Shared.Enums;

namespace AuthenticationService.Shared.Dtos.Response;

/// <summary>
/// MFA sub-record used by <see cref="UserDetailDto"/>.
/// </summary>
public class MfaInfoDto
{
    /// <summary>Reflects Identity's <c>TwoFactorEnabled</c> column.</summary>
    public bool Enabled { get; set; }

    /// <summary>Which provider the user prefers for the MFA challenge (authenticator app, email, SMS).</summary>
    public MfaProviders PreferredProvider { get; set; }
}
