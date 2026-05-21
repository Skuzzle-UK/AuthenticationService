using System.ComponentModel.DataAnnotations;

namespace AuthenticationService.TokenClientLib;

/// <summary>
/// Configuration for the outgoing-token client — what's needed to call
/// <c>/oauth/token</c> and cache the result. Bind via
/// <c>AddAuthenticationServiceTokenClient(config.GetSection("AuthenticationService"))</c>.
/// </summary>
public class ServiceTokenClientOptions
{
    /// <summary>
    /// Base URL of the AuthenticationService. Used to discover <c>token_endpoint</c>
    /// via the OIDC discovery doc unless <see cref="TokenEndpointOverride"/> is set.
    /// </summary>
    [Required]
    public string? Authority { get; set; }

    /// <summary>
    /// The <c>client_id</c> issued when this client was provisioned.
    /// </summary>
    [Required]
    public string? ClientId { get; set; }

    /// <summary>
    /// Plaintext client secret. Treat as sensitive credential material — source from
    /// a secret store / env var / user secrets, never committed config.
    /// </summary>
    [Required]
    public string? ClientSecret { get; set; }

    /// <summary>
    /// If set, skips OIDC discovery and uses this URL directly. Intended for tests
    /// and air-gapped environments.
    /// </summary>
    public string? TokenEndpointOverride { get; set; }

    /// <summary>
    /// Whether OIDC discovery requires HTTPS. Defaults to true.
    /// </summary>
    public bool RequireHttpsMetadata { get; set; } = true;

    /// <summary>
    /// Fraction of the token's lifetime after which the cache proactively refreshes
    /// in the background on the next call. Past expiry, refresh is synchronous.
    /// </summary>
    [Range(0.0, 1.0, ErrorMessage = "RefreshAtFractionOfLifetime must be in [0.0, 1.0).")]
    public double RefreshAtFractionOfLifetime { get; set; } = 0.8;

    /// <summary>
    /// Maximum retries against <c>/oauth/token</c> on 5xx / transient network error.
    /// 4xx responses are never retried. Backoff is exponential (250ms, 500ms, 1s, ...).
    /// </summary>
    [Range(0, 10)]
    public int MaxRetriesOnTransient { get; set; } = 3;
}
