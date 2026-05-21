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
/// OAuth 2.0 token endpoint (RFC 6749). Supports only the <c>client_credentials</c> grant. Error descriptions are deliberately bland so attackers can't enumerate valid client IDs.
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
    /// RFC 6749 §4.4 client-credentials grant.
    /// </summary>
    [HttpPost("token")]
    [Consumes("application/x-www-form-urlencoded")]
    public async Task<IActionResult> TokenAsync([FromForm] OAuthTokenRequest request, CancellationToken ct)
    {
        // Config-gated so integration tests can drive the endpoint over HTTP. Production keeps RequireHttps=true.
        if (_settings.RequireHttps && !Request.IsHttps)
        {
            return Deny("invalid_request", "HTTPS is required for this endpoint.");
        }

        if (!string.Equals(request.GrantType, GrantTypeClientCredentials, StringComparison.Ordinal))
        {
            return Deny("unsupported_grant_type",
                $"Only '{GrantTypeClientCredentials}' is supported by this endpoint.");
        }

        if (!TryExtractCredentials(request, out var clientId, out var clientSecret, out var credentialError))
        {
            return Deny("invalid_request", credentialError);
        }

        // FindActiveAsync returns null for both "no such client" AND "disabled" so the response can't enumerate valid IDs.
        var client = await _clientService.FindActiveAsync(clientId!, ct);
        if (client is null || !_clientService.VerifySecret(client, clientSecret!))
        {
            return DenyInvalidClient();
        }

        // Audience + scope are both required. RFC allows scope optional but we require it — service tokens must always carry a bounded scope set.
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

        // All-or-nothing: one unknown scope fails the whole request.
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

    // Prefers Authorization: Basic (RFC 6749 §2.3.1); falls back to body fields. Returns false if neither source yields both, or if the two disagree.
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

        // If header was present, body MUST match (or be empty); otherwise body fills in.
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

    // 400 + standard RFC 6749 §5.2 error-response shape.
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

    // 401 + WWW-Authenticate: Basic per RFC 6749 §5.2 — signals retry-with-credentials rather than malformed-request.
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
