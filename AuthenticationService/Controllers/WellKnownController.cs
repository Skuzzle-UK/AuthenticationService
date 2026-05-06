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
    private readonly IEcdsaKeyProvider _keyProvider;
    private readonly JWTSettings _jwtSettings;

    public WellKnownController(IEcdsaKeyProvider keyProvider, IOptions<JWTSettings> jwtSettings)
    {
        _keyProvider = keyProvider;
        _jwtSettings = jwtSettings.Value;
    }

    /// <summary>
    /// Returns every public signing key the service currently knows about. During key
    /// rotation the active key plus any predecessors are all published here so consumers
    /// can validate tokens issued by any of them — the JWT's <c>kid</c> header tells
    /// JwtBearer which to use.
    /// </summary>
    [HttpGet(WellKnownPaths.Jwks)]
    public IActionResult Jwks()
    {
        var keys = _keyProvider.PublicJsonWebKeys.Select(jwk => new
        {
            kty = jwk.Kty,
            crv = jwk.Crv,
            x   = jwk.X,
            y   = jwk.Y,
            use = jwk.Use,
            alg = jwk.Alg,
            kid = jwk.Kid,
        });

        return Ok(new { keys });
    }

    /// <summary>
    /// Minimal OIDC discovery document. Lets consumers configure JwtBearer with just `Authority`.
    /// </summary>
    [HttpGet(WellKnownPaths.OpenIdConfiguration)]
    public IActionResult OpenIdConfiguration()
    {
        var issuer = _jwtSettings.ValidIssuer;
        var jwksUri = $"{Request.Scheme}://{Request.Host}{Request.PathBase}/{WellKnownPaths.Prefix}/{WellKnownPaths.Jwks}";

        return Ok(new
        {
            issuer,
            jwks_uri = jwksUri,
            id_token_signing_alg_values_supported = new[] { SecurityAlgorithms.EcdsaSha256 },
            response_types_supported = new[] { "token" },
            subject_types_supported = new[] { "public" },
        });
    }
}
