#pragma warning disable CS8618 // Uninitialised non-nullable — properties bound by the Options pipeline at startup.
using System.ComponentModel.DataAnnotations;

namespace AuthenticationService.Settings;

/// <summary>
/// JWT signing and validation config.
/// </summary>
public class JWTSettings
{
    /// <summary>
    /// Directory of ES256 PEM private keys. Every PEM is loaded and published in the JWKS.
    /// In Development an empty directory triggers auto-generation; in non-Development it
    /// throws at startup — keys must be provisioned by the deploy pipeline.
    /// </summary>
    [Required]
    public string PrivateKeyDirectory { get; set; }

    /// <summary>
    /// Active signing key thumbprint, or <c>"auto"</c> to pick the first key found.
    /// Set explicitly during rotation to swap signers while keeping old keys in the JWKS.
    /// </summary>
    public string ActiveKeyId { get; set; } = "auto";

    /// <summary>
    /// The <c>iss</c> claim. Consumers validate against this.
    /// </summary>
    [Required]
    public string ValidIssuer { get; set; }

    /// <summary>
    /// The <c>aud</c> claim. Every consuming microservice must match it.
    /// </summary>
    [Required]
    public string ValidAudience { get; set; }

    /// <summary>
    /// How long an access token is valid for, in minutes. Short by design — the refresh flow rolls fresh ones quickly.
    /// </summary>
    [Required, Range(1, 1440)]
    public int ExpiryInMinutes { get; set; }

    /// <summary>
    /// How long a refresh token is valid for, in days. After this they're pruned by the cleanup sweep.
    /// </summary>
    [Required, Range(1, 365)]
    public int RefreshTokenExpiryInDays { get; set; }
}
