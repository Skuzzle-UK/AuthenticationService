namespace AuthenticationService.Settings;

/// <summary>
/// X.509 certificate source for data-protection at-rest encryption. Currently PFX only.
/// </summary>
public class DataProtectionCertificateSettings
{
    /// <summary>
    /// Path to a PFX file containing the cert + private key.
    /// </summary>
    public string? PfxPath { get; set; }

    /// <summary>
    /// Null if the PFX is unprotected.
    /// </summary>
    public string? PfxPassword { get; set; }
}
