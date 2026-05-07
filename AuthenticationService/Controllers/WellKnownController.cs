using AuthenticationService.Constants;
using AuthenticationService.Services;
using AuthenticationService.Settings;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;

namespace AuthenticationService.Controllers;

/// <summary>
/// Serves OIDC discovery and JWKS metadata used by token-consuming services.
/// </summary>
[ApiController]
[AllowAnonymous]
[Route(WellKnownPaths.Prefix)]
public class WellKnownController : ControllerBase
{
    private const int CacheSeconds = 3600;

    private readonly IEcdsaKeyProvider _keyProvider;
    private readonly JWTSettings _jwtSettings;
    private readonly PublicUrlSettings _publicUrlSettings;

    public WellKnownController(
        IEcdsaKeyProvider keyProvider,
        IOptions<JWTSettings> jwtSettings,
        IOptions<PublicUrlSettings> publicUrlSettings)
    {
        _keyProvider = keyProvider;
        _jwtSettings = jwtSettings.Value;
        _publicUrlSettings = publicUrlSettings.Value;
    }

    /// <summary>
    /// Returns every public signing key the service currently knows about. During key
    /// rotation the active key plus any predecessors are all published here so consumers
    /// can validate tokens issued by any of them — the JWT's <c>kid</c> header tells
    /// JwtBearer which to use.
    /// </summary>
    [HttpGet(WellKnownPaths.Jwks)]
    [ResponseCache(Duration = CacheSeconds, Location = ResponseCacheLocation.Any)]
    public IActionResult Jwks() => Ok(_keyProvider.JwksDocument);

    /// <summary>
    /// Minimal OIDC discovery document. Lets consumers configure JwtBearer with just `Authority`.
    /// </summary>
    [HttpGet(WellKnownPaths.OpenIdConfiguration)]
    [ResponseCache(Duration = CacheSeconds, Location = ResponseCacheLocation.Any)]
    public IActionResult OpenIdConfiguration()
    {
        // Use the configured public base URL rather than request-derived scheme/host so
        // the discovery doc advertises the canonical name even behind a reverse proxy
        // that doesn't preserve Host (we deliberately don't honour X-Forwarded-Host —
        // host-header attack surface).
        var jwksUri = $"{_publicUrlSettings.BaseUrl}/{WellKnownPaths.Prefix}/{WellKnownPaths.Jwks}";

        return Ok(new
        {
            issuer = _jwtSettings.ValidIssuer,
            jwks_uri = jwksUri,
            id_token_signing_alg_values_supported = new[] { SecurityAlgorithms.EcdsaSha256 },
        });
    }
}
