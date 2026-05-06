#pragma warning disable
using System.ComponentModel.DataAnnotations;

namespace AuthenticationService.Settings;

/// <summary>
/// Configuration for JWT signing and validation. Bound from the <c>JWTSettings</c> section
/// of <c>appsettings.json</c> (or env vars / user-secrets in dev / a secret store in prod).
/// </summary>
public class JWTSettings
{
    /// <summary>
    /// Directory containing one or more ES256 PEM-encoded private keys (<c>*.pem</c>). Every
    /// PEM in the directory is loaded and published in the JWKS for validation. The active
    /// signing key is the one whose thumbprint matches <see cref="ActiveKeyId"/>, or — if
    /// <c>ActiveKeyId</c> is <c>"auto"</c> or empty — the first key found (deterministic for
    /// single-key dev setups). Relative paths resolve against the content root.
    ///
    /// <para>In Development, an empty directory triggers auto-generation of a single key so
    /// <c>dotnet run</c> works first time. In non-Development environments, an empty
    /// directory throws at startup — keys must be provisioned by the deploy pipeline.</para>
    /// </summary>
    [Required]
    public string PrivateKeyDirectory { get; set; }

    /// <summary>
    /// Thumbprint of the key that should sign newly-issued tokens. Set to <c>"auto"</c>
    /// (the default) to use the first key found in the directory — fine for single-key
    /// setups and dev. During rotation, set this explicitly to the new key's thumbprint
    /// to designate it as active without removing the previous key from the JWKS.
    /// Thumbprints are logged at startup so operators can read them off the log.
    /// </summary>
    public string ActiveKeyId { get; set; } = "auto";

    /// <summary>The <c>iss</c> claim stamped onto issued tokens. Consumers validate against this.</summary>
    [Required]
    public string ValidIssuer { get; set; }

    /// <summary>
    /// The <c>aud</c> claim stamped onto issued tokens. Every consuming microservice must be
    /// configured with the same value or its JwtBearer middleware will reject the token.
    /// </summary>
    [Required]
    public string ValidAudience { get; set; }

    /// <summary>How long an access token is valid for, in minutes. Short by design — the refresh flow rolls fresh ones quickly.</summary>
    [Required]
    public double ExpiryInMinutes { get; set; }

    /// <summary>How long a refresh token is valid for, in days. After this they're pruned by the cleanup sweep.</summary>
    [Required]
    public double RefreshTokenExpiryInDays { get; set; }
}
