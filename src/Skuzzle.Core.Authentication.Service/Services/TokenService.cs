using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Logging;
using Microsoft.IdentityModel.Tokens;
using Skuzzle.Core.Authentication.Lib.Models;
using Skuzzle.Core.Authentication.Service.Settings;
using Skuzzle.Core.Lib.ResultClass;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;

namespace Skuzzle.Core.Authentication.Service.Services;

public class TokenService : ITokenService
{
    private readonly IMemoryCache _refreshTokenCache;

    private readonly JwtSettings _jwtSettings;

    public TokenService(
        IMemoryCache refreshTokenCache,
        IOptions<JwtSettings> settings)
    {
        _refreshTokenCache = refreshTokenCache;
        _jwtSettings = settings.Value;
    }

    public Token GetNewToken(User user)
    {
        //TODO: Add a tonne of claims /nb
        var claims = new List<Claim>()
        {
            new Claim("UserId", user.Id.ToString()),
            new Claim(ClaimTypes.Name, user.Username),
            new Claim(ClaimTypes.Role, string.Join(",", user.Roles))
        };

        var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_jwtSettings.Key));

        var cred = new SigningCredentials(key, SecurityAlgorithms.HmacSha512Signature);

        var now = DateTimeOffset.UtcNow;

        var expires = now.AddSeconds(_jwtSettings.TtlSeconds);

        var token = new JwtSecurityToken(
            claims: claims,
            expires: expires.UtcDateTime,
            signingCredentials: cred,
            issuer: _jwtSettings.Issuer,
            audience: _jwtSettings.Audience);

        var AccessToken = new JwtSecurityTokenHandler().WriteToken(token);

        var refreshToken = GenerateRefreshToken();
        var refreshExpires = now.AddSeconds(_jwtSettings.RefreshTtlSeconds);

        _refreshTokenCache.Set(user.Id, refreshToken, refreshExpires);

        return new Token(user.Id, AccessToken, expires, refreshToken, refreshExpires);
    }



    public Token? RefreshToken(User user, string refreshToken)
    {
        if (!_refreshTokenCache.TryGetValue(user.Id, out string? cachedRefreshToken))
        {
            return null;
        }

        // Remove refresh token from cache for user.Id as this could be malicious activity
        if (cachedRefreshToken != refreshToken)
        {
            _refreshTokenCache.Remove(user.Id);
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

    public Result<ClaimsPrincipal> ValidateToken(string token, bool validateLifetime)
    {
        try
        {
            IdentityModelEventSource.ShowPII = true;
            var validationParameters = new TokenValidationParameters();

            validationParameters.ValidateLifetime = validateLifetime;

            validationParameters.ValidAudience = _jwtSettings.Audience;
            validationParameters.ValidIssuer = _jwtSettings.Issuer;
            validationParameters.IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_jwtSettings.Key));

            return Result.Ok(new JwtSecurityTokenHandler().ValidateToken(token, validationParameters, out _));
        }
        catch (Exception ex)
        {
            return Result.Fail<ClaimsPrincipal>(ex, ex.Message);
        }
    }
}
