using System.Text;
using AuthenticationService.Constants;
using AuthenticationService.Extensions;
using AuthenticationService.Observability;
using AuthenticationService.Services;
using AuthenticationService.Settings;
using AuthenticationService.Shared.Constants;
using AuthenticationService.Shared.Dtos.Response;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.Extensions.Options;
using Microsoft.Net.Http.Headers;

namespace AuthenticationService.Controllers;

/// <summary>
/// OAuth 2.0 token endpoint (RFC 6749). Currently supports only the
/// <c>client_credentials</c> grant — the service-to-service identity flow. Consumers
/// POST their <c>client_id</c> / <c>client_secret</c> (Basic auth header or
/// form-encoded body), the requested <c>audience</c>, and a space-separated
/// <c>scope</c> list, and get back a JWT they can use as a Bearer token against
/// downstream services.
///
/// <para>Anonymous + rate-limited (<see cref="RateLimitPolicies.AuthStrict"/> — 10/min
/// per IP). Errors follow RFC 6749 §5.2: <c>{ "error": "...", "error_description": "..." }</c>
/// with the standard error codes. Error descriptions are deliberately bland so an
/// attacker can't enumerate valid client IDs by response-text differences.</para>
/// </summary>
[Route("oauth")]
[ApiController]
[AllowAnonymous]
[EnableRateLimiting(RateLimitPolicies.AuthStrict)]
public class OAuthController : ControllerBase
{
    private const string GrantTypeClientCredentials = "client_credentials";

    private readonly IClientService _clientService;
    private readonly ITokenService _tokenService;
    private readonly ClientCredentialsSettings _settings;
    private readonly ILogger<OAuthController> _logger;
    private readonly AuthMetrics _metrics;

    public OAuthController(
        IClientService clientService,
        ITokenService tokenService,
        IOptions<ClientCredentialsSettings> settings,
        ILogger<OAuthController> logger,
        AuthMetrics metrics)
    {
        _clientService = clientService;
        _tokenService = tokenService;
        _settings = settings.Value;
        _logger = logger;
        _metrics = metrics;
    }

    /// <summary>
    /// RFC 6749 §4.4 client-credentials grant. See class summary for the contract.
    /// </summary>
    [HttpPost("token")]
    [Consumes("application/x-www-form-urlencoded")]
    public async Task<IActionResult> TokenAsync([FromForm] OAuthTokenRequest request, CancellationToken ct)
    {
        // HTTPS check — config-gated so integration tests can drive the endpoint over
        // HTTP. Production keeps RequireHttps=true.
        if (_settings.RequireHttps && !Request.IsHttps)
        {
            return Deny("invalid_request", "HTTPS is required for this endpoint.");
        }

        // Grant type — only client_credentials is supported.
        if (!string.Equals(request.GrantType, GrantTypeClientCredentials, StringComparison.Ordinal))
        {
            return Deny("unsupported_grant_type",
                $"Only '{GrantTypeClientCredentials}' is supported by this endpoint.");
        }

        // Extract credentials. Basic auth header preferred (RFC 6749 §2.3.1); body
        // fallback for clients that can't easily set headers. If both are present and
        // disagree, that's a malformed request.
        if (!TryExtractCredentials(request, out var clientId, out var clientSecret, out var credentialError))
        {
            return Deny("invalid_request", credentialError);
        }

        // Find + verify. FindActiveAsync returns null for both "no such client" AND
        // "disabled client" so the response can't be used to enumerate valid IDs.
        var client = await _clientService.FindActiveAsync(clientId!, ct);
        if (client is null || !_clientService.VerifySecret(client, clientSecret!))
        {
            return DenyInvalidClient();
        }

        // Audience + scope are both required for this grant. RFC technically allows
        // scope to be optional but we require it — service tokens must always carry a
        // bounded scope set.
        if (string.IsNullOrWhiteSpace(request.Audience))
        {
            return Deny("invalid_request", "audience is required.");
        }
        if (string.IsNullOrWhiteSpace(request.Scope))
        {
            return Deny("invalid_request", "scope is required.");
        }

        var scopes = request.Scope
            .Split(' ', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Distinct(StringComparer.Ordinal)
            .ToArray();
        if (scopes.Length == 0)
        {
            return Deny("invalid_request", "scope is required.");
        }

        // Authorise each requested scope against the client's allow-list. One unknown
        // scope fails the whole request — there's no concept of "give me what you can"
        // here, the caller asked for X and either gets X or gets nothing.
        foreach (var scope in scopes)
        {
            if (!await _clientService.HasScopeAsync(clientId!, request.Audience!, scope, ct))
            {
                _logger.LogWarning(
                    SecurityEventIds.ClientCredentialsTokenDenied,
                    "Client {ClientId} requested unauthorised scope {Scope} for audience {Audience} from {IpAddress}",
                    clientId,
                    scope,
                    request.Audience,
                    Request.GetRemoteIpAddress());
                _metrics.ClientCredentialsTokenDenied("invalid_scope");
                return BadRequest(new OAuthErrorResponse
                {
                    Error = "invalid_scope",
                    ErrorDescription = "One or more requested scopes are not authorised for this client/audience.",
                });
            }
        }

        // Issue the token + record the activity.
        var token = await _tokenService.CreateServiceTokenAsync(clientId!, request.Audience!, scopes);
        await _clientService.TouchLastUsedAsync(clientId!, ct);

        _logger.LogInformation(
            SecurityEventIds.ClientCredentialsTokenIssued,
            "Issued service token for client {ClientId} audience {Audience} scopes {Scopes} from {IpAddress}",
            clientId,
            request.Audience,
            string.Join(' ', scopes),
            Request.GetRemoteIpAddress());
        _metrics.ClientCredentialsTokenIssued();

        // expires_in is seconds-until-expiry. Always positive (the token-gen method
        // computes Expires from UtcNow + the configured lifetime).
        var expiresIn = (int)Math.Max(0, (token.Expires!.Value - DateTime.UtcNow).TotalSeconds);

        return Ok(new OAuthTokenResponse
        {
            AccessToken = token.Value,
            TokenType = AuthSchemeConstants.Bearer,
            ExpiresIn = expiresIn,
            Scope = string.Join(' ', scopes),
        });
    }

    // ─── Helpers ───────────────────────────────────────────────────────────────────

    /// <summary>
    /// Pulls client_id + client_secret out of the request. Prefers the
    /// <c>Authorization: Basic</c> header (RFC 6749 §2.3.1); falls back to the body
    /// fields. Returns false (with <paramref name="error"/> populated) if neither
    /// source yields both fields, or if the two sources disagree.
    /// </summary>
    private bool TryExtractCredentials(
        OAuthTokenRequest request,
        out string? clientId,
        out string? clientSecret,
        out string error)
    {
        clientId = null;
        clientSecret = null;
        error = string.Empty;

        var authHeader = Request.Headers[HeaderNames.Authorization].ToString();
        if (!string.IsNullOrEmpty(authHeader))
        {
            if (!authHeader.StartsWith("Basic ", StringComparison.OrdinalIgnoreCase))
            {
                error = "Only Basic authentication is supported on this endpoint.";
                return false;
            }

            try
            {
                var encoded = authHeader["Basic ".Length..].Trim();
                var decoded = Encoding.UTF8.GetString(Convert.FromBase64String(encoded));
                var colon = decoded.IndexOf(':');
                if (colon < 0)
                {
                    error = "Malformed Basic authorization header.";
                    return false;
                }
                clientId = decoded[..colon];
                clientSecret = decoded[(colon + 1)..];
            }
            catch (FormatException)
            {
                error = "Malformed Basic authorization header — bad base64.";
                return false;
            }
        }

        // Body fields. If header was present, the body MUST match (or be empty); if
        // not present, the body fills in.
        if (!string.IsNullOrEmpty(request.ClientId))
        {
            if (clientId is not null && !string.Equals(clientId, request.ClientId, StringComparison.Ordinal))
            {
                error = "client_id in body disagrees with Basic auth header.";
                return false;
            }
            clientId ??= request.ClientId;
        }
        if (!string.IsNullOrEmpty(request.ClientSecret))
        {
            if (clientSecret is not null && !string.Equals(clientSecret, request.ClientSecret, StringComparison.Ordinal))
            {
                error = "client_secret in body disagrees with Basic auth header.";
                return false;
            }
            clientSecret ??= request.ClientSecret;
        }

        if (string.IsNullOrEmpty(clientId) || string.IsNullOrEmpty(clientSecret))
        {
            error = "client_id and client_secret are required (via Basic auth header or form body).";
            return false;
        }
        return true;
    }

    /// <summary>
    /// Emits the standard error-response shape for non-credential failures
    /// (invalid_request / unsupported_grant_type). Always 400 per RFC 6749 §5.2.
    /// </summary>
    private IActionResult Deny(string error, string? description)
    {
        _logger.LogWarning(
            SecurityEventIds.ClientCredentialsTokenDenied,
            "OAuth token request denied from {IpAddress} ({Reason}: {Description})",
            Request.GetRemoteIpAddress(),
            error,
            description);
        _metrics.ClientCredentialsTokenDenied(error);
        return BadRequest(new OAuthErrorResponse
        {
            Error = error,
            ErrorDescription = description,
        });
    }

    /// <summary>
    /// 401 + <c>WWW-Authenticate: Basic</c> for invalid_client per RFC 6749 §5.2 —
    /// signals to a Basic-auth client that it should retry with valid credentials
    /// rather than treating this as a malformed request.
    /// </summary>
    private IActionResult DenyInvalidClient()
    {
        _logger.LogWarning(
            SecurityEventIds.ClientCredentialsTokenDenied,
            "OAuth token request denied from {IpAddress} (invalid_client)",
            Request.GetRemoteIpAddress());
        _metrics.ClientCredentialsTokenDenied("invalid_client");

        Response.Headers[HeaderNames.WWWAuthenticate] = "Basic realm=\"oauth\"";
        return Unauthorized(new OAuthErrorResponse
        {
            Error = "invalid_client",
            ErrorDescription = "Client authentication failed.",
        });
    }
}
