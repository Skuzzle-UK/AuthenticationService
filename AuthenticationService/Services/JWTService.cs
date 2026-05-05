using AuthenticationService.Constants;
using AuthenticationService.Entities;
using AuthenticationService.Enums;
using AuthenticationService.Settings;
using AuthenticationService.Shared.Constants;
using AuthenticationService.Shared.Models;
using AuthenticationService.Storage;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;

namespace AuthenticationService.Services;

public class JWTService : ITokenService
{
    private readonly JWTSettings _jwtSettings;
    private readonly UserManager<User> _userManager;
    private readonly DatabaseContext _context;
    private readonly IEcdsaKeyProvider _keyProvider;

    public JWTService(
        IOptions<JWTSettings> jwtSettings,
        UserManager<User> userManager,
        DatabaseContext context,
        IEcdsaKeyProvider keyProvider)
    {
        _jwtSettings = jwtSettings.Value;
        _userManager = userManager;
        _context = context;
        _keyProvider = keyProvider;
    }

    public async Task<Token> CreateTokenAsync(User user, IList<string> roles)
    {
        var claims = GetClaims(user, roles);
        var tokenOptions = GenerateTokenOptions(_keyProvider.SigningCredentials, claims);
        user.RefreshToken = GenerateRefreshToken();
        user.RefreshTokenExpiresAt = DateTime.UtcNow.AddDays(_jwtSettings.RefreshTokenExpiryInDays);

        await _userManager.UpdateAsync(user);

        return new Token(
            AuthSchemeConstants.Bearer,
            new JwtSecurityTokenHandler().WriteToken(tokenOptions),
            tokenOptions.ValidTo,
            user.RefreshToken,
            user.RefreshTokenExpiresAt);
    }

    public async Task<bool> ValidateExpiredTokenAsync(string token)
    {
        var tokenHandler = new JwtSecurityTokenHandler();
        
        var parameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidateAudience = true,
            ValidateIssuerSigningKey = true,
            ValidateLifetime = false,
            ValidIssuer = _jwtSettings.ValidIssuer,
            ValidAudience = _jwtSettings.ValidAudience,
            IssuerSigningKey = _keyProvider.PublicSecurityKey,
            ValidAlgorithms = [SecurityAlgorithms.EcdsaSha256]
        };

        var validationResult = await tokenHandler.ValidateTokenAsync(token, parameters);
        return validationResult.IsValid;
    }

    public async Task RevokeTokenAsync(string token, string ipaddress)
    {
        var jti = GetJtiFromToken(token);

        var revokedToken = new RevokedToken()
        {
            TokenJti = jti,
            ExpiresAt = GetExpiryDateTime(token),
            UserId = GetUserId(token)
        };

        await _context.RevokedTokens.AddAsync(revokedToken);
        await _context.SaveChangesAsync();
    }

    public async Task<bool> IsRevokedAsync(string token)
    {
        var jti = GetJtiFromToken(token);
        return await _context.RevokedTokens.AnyAsync(t => t.TokenJti == jti);
    }

    public async Task RecordAccessAttemptAsync(string token, string ipAddress)
    {
        var jti = GetJtiFromToken(token);
        var severity = Severity.Low;
        var isRevoked = false;

        var revokedToken = await _context.RevokedTokens.FindAsync(jti);
        if (revokedToken is not null)
        {
            isRevoked = true;

            severity = revokedToken.ExpiresAt.HasValue && revokedToken.ExpiresAt.Value < DateTime.UtcNow
                ? Severity.Low
                : Severity.Medium;
        }

        var accessRecord = new AccessRecord()
        {
            TokenJti = jti,
            IpAddress = ipAddress,
            CreatedAt = DateTime.UtcNow,
            UserId = GetUserId(token),
            Revoked = isRevoked,
            Severity = severity
        };

        await _context.AccessRecords.AddAsync(accessRecord);
        await _context.SaveChangesAsync();
    }

    public string GetUserId(string token)
    {
        var handler = new JwtSecurityTokenHandler();
        var jwtToken = handler.ReadJwtToken(token);

        return jwtToken.Claims.FirstOrDefault(c => c.Type == ClaimConstants.Sub)?.Value ?? string.Empty;
    }

    private static string GetJtiFromToken(string token)
    {
        var tokenHandler = new JwtSecurityTokenHandler();

        if (tokenHandler.ReadToken(token) is not JwtSecurityToken jwtToken)
        {
            throw new UnauthorizedAccessException(ErrorMessageConstants.InvalidToken);
        }

        var jti = jwtToken.Claims.FirstOrDefault(claim => claim.Type == ClaimConstants.Jti)?.Value;
        
        return jti
            ?? throw new UnauthorizedAccessException(ErrorMessageConstants.MissingJtiClaim);
    }

    private static string GenerateRefreshToken()
    {
        var randomNumber = new byte[32];
        using (var rng = RandomNumberGenerator.Create())
        {
            rng.GetBytes(randomNumber);
            return Convert.ToBase64String(randomNumber);
        }
    }

    public DateTime? GetExpiryDateTime(string token)
    {
        var tokenHandler = new JwtSecurityTokenHandler();

        if (tokenHandler.ReadToken(token) is not JwtSecurityToken jwtToken)
        {
            return null;
        }

        var expClaim = jwtToken.Claims.FirstOrDefault(claim => claim.Type == ClaimConstants.Exp)?.Value;
        if (expClaim == null)
        {
            return null;
        }

        return DateTimeOffset.FromUnixTimeSeconds(long.Parse(expClaim)).UtcDateTime;
    }

    private static List<Claim> GetClaims(User user, IList<string> roles)
    {
        var claims = new List<Claim>()
        {
            new(ClaimConstants.Sub, user.Id),
            new(ClaimConstants.Jti, Guid.NewGuid().ToString()),
            new(ClaimConstants.Name, user.UserName!),
            new(ClaimConstants.Email, user.Email!)
        };

        foreach (var role in roles)
        {
            claims.Add(new Claim(ClaimConstants.Role, role));
        }

        return claims;
    }

    private JwtSecurityToken GenerateTokenOptions(SigningCredentials signingCredentials, List<Claim> claims)
    {
        var tokenOptions = new JwtSecurityToken(
            issuer: _jwtSettings.ValidIssuer,
            audience: _jwtSettings.ValidAudience,
            claims: claims,
            expires: DateTime.UtcNow.AddMinutes(_jwtSettings.ExpiryInMinutes),
            signingCredentials: signingCredentials);

        return tokenOptions;
    }
}
