using System.ComponentModel.DataAnnotations;

namespace AuthenticationService.TokenClientLib;

/// <summary>
/// Configuration for the outgoing-token side of the AuthenticationService client libs —
/// what's needed to call <c>/oauth/token</c> and cache the result. Distinct from the
/// validation-side <c>AuthenticationServiceOptions</c> (in
/// <c>AuthenticationService.TokenValidationLib</c>) because the two halves are
/// orthogonal — a service might validate incoming tokens without making outgoing
/// calls, or vice versa, and they're shipped as separate NuGets.
///
/// <para>Bind from configuration via
/// <c>services.AddAuthenticationServiceTokenClient(config.GetSection("AuthenticationService"))</c>.</para>
/// </summary>
public class ServiceTokenClientOptions
{
    /// <summary>
    /// Base URL of the AuthenticationService — same value as the validation lib's
    /// <c>AuthenticationServiceOptions.Authority</c>. Used to discover
    /// <c>token_endpoint</c> via the OIDC discovery doc unless
    /// <see cref="TokenEndpointOverride"/> is set.
    /// </summary>
    [Required]
    public string? Authority { get; set; }

    /// <summary>
    /// The <c>client_id</c> issued by the admin when this client was provisioned.
    /// </summary>
    [Required]
    public string? ClientId { get; set; }

    /// <summary>
    /// The plaintext client secret from the create / rotate response. Treat as
    /// sensitive credential material — source from a secret store / env var / user
    /// secrets, never committed config.
    /// </summary>
    [Required]
    public string? ClientSecret { get; set; }

    /// <summary>
    /// If set, skips OIDC discovery and uses this URL directly. Useful for tests and
    /// air-gapped environments. Production should leave this unset and let discovery
    /// resolve the endpoint dynamically.
    /// </summary>
    public string? TokenEndpointOverride { get; set; }

    /// <summary>
    /// Whether OIDC discovery requires HTTPS. Defaults to true; tests can flip off.
    /// </summary>
    public bool RequireHttpsMetadata { get; set; } = true;

    /// <summary>
    /// Fraction of the issued token's lifetime after which the cache will proactively
    /// refresh on the next call. At <c>0.8</c> and a 12h token, a call between minutes
    /// 0–576 returns the cached token unchanged; a call after minute 576 returns the
    /// current token AND fires a background refresh; a call after expiry (720m) blocks
    /// on synchronous refresh.
    /// </summary>
    [Range(0.0, 1.0, ErrorMessage = "RefreshAtFractionOfLifetime must be in [0.0, 1.0).")]
    public double RefreshAtFractionOfLifetime { get; set; } = 0.8;

    /// <summary>
    /// Maximum retries against <c>/oauth/token</c> on 5xx or transient network error.
    /// 4xx responses are never retried regardless. Backoff is exponential (250ms,
    /// 500ms, 1s, ...).
    /// </summary>
    [Range(0, 10)]
    public int MaxRetriesOnTransient { get; set; } = 3;
}
