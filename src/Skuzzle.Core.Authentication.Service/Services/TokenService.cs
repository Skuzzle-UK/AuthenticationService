using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Logging;
using Microsoft.IdentityModel.Tokens;
using Skuzzle.Core.Authentication.Lib.Models;
using Skuzzle.Core.Authentication.Service.Settings;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;

namespace Skuzzle.Core.Authentication.Service.Services;

public class TokenService : ITokenService
{
    private readonly IMemoryCache _refreshTokenCache;

    private readonly string _securityKey;
    private readonly string _issuer;
    private readonly string _audience;

    public TokenService(
        IMemoryCache refreshTokenCache,
        IOptions<JwtSettings> settings)
    {
        _refreshTokenCache = refreshTokenCache;


        _securityKey = settings.Value.Key;
        _issuer = settings.Value.Issuer;
        _audience = settings.Value.Audience;
    }

    public Token GetNewToken(User user)
    {
        //TODO: Add a tonne of claims /nb
        List<Claim> claims = new List<Claim>()
        {
            new Claim("UserId", user.Id.ToString()),
            new Claim(ClaimTypes.Name, user.Username),
            new Claim(ClaimTypes.Role, string.Join(",", user.Roles))
        };

        var key = new SymmetricSecurityKey(System.Text.Encoding.UTF8.GetBytes(_securityKey));

        var cred = new SigningCredentials(key, SecurityAlgorithms.HmacSha512Signature);

        var now = DateTimeOffset.UtcNow;

        var expires = now.AddSeconds(300);

        var token = new JwtSecurityToken(
            claims: claims,
            expires: expires.UtcDateTime,
            signingCredentials: cred,
            issuer: _issuer,
            audience: _audience);

        var AccessToken = new JwtSecurityTokenHandler().WriteToken(token);

        var refreshToken = GenerateRefreshToken();
        var refreshExpires = now.AddSeconds(1800);

        _refreshTokenCache.Set(user.Id, refreshToken, refreshExpires);

        return new Token(user.Id, AccessToken, expires, refreshToken, refreshExpires);
    }



    public Token? RefreshToken(User user, string refreshToken)
    {
        if (!_refreshTokenCache.TryGetValue(user.Id, out string? cachedRefreshToken) || cachedRefreshToken != refreshToken)
        {
            return null;
        }

        return GetNewToken(user);
    }

    private string GenerateRefreshToken()
    {
        var randomNumber = new byte[64];
        using var rng = RandomNumberGenerator.Create();
        rng.GetBytes(randomNumber);
        return Convert.ToBase64String(randomNumber);
    }

    public ClaimsPrincipal ValidateToken(string token, bool validateLifetime)
    {
        IdentityModelEventSource.ShowPII = true;

        SecurityToken validatedToken;
        TokenValidationParameters validationParameters = new TokenValidationParameters();

        validationParameters.ValidateLifetime = validateLifetime;

        validationParameters.ValidAudience = _audience;
        validationParameters.ValidIssuer = _issuer;
        validationParameters.IssuerSigningKey = new Microsoft.IdentityModel.Tokens.SymmetricSecurityKey(Encoding.UTF8.GetBytes(_securityKey));

        ClaimsPrincipal principal = new JwtSecurityTokenHandler().ValidateToken(token, validationParameters, out validatedToken);


        return principal;
    }
}
