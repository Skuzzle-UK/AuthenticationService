namespace AuthenticationService.Settings;

/// <summary>
/// Source for the X.509 certificate used to protect data-protection keys at rest.
/// Currently supports loading from a PFX file. Extensible — additional sources (Windows
/// store thumbprint, base64-inline, secret manager) can be added without changing callers.
/// </summary>
public class DataProtectionCertificateSettings
{
    /// <summary>
    /// Path to a PFX file containing the cert + private key.
    /// </summary>
    public string? PfxPath { get; set; }

    /// <summary>
    /// Password protecting the PFX. Leave null if the PFX is unprotected.
    /// </summary>
    public string? PfxPassword { get; set; }
}
