using AuthenticationService.Entities;
using AuthenticationService.Settings;
using AuthenticationService.Shared.Models;
using AuthenticationService.Storage;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;

namespace AuthenticationService.Services;

public class JWTService : ITokenService
{
    private readonly JWTSettings _jwtSettings;
    private readonly UserManager<User> _userManager;
    private readonly DatabaseContext _context;

    public JWTService(
        IOptions<JWTSettings> jwtSettings,
        UserManager<User> userManager,
        DatabaseContext context)
    {
        _jwtSettings = jwtSettings.Value;
        _userManager = userManager;
        _context = context;
    }

    public async Task<Token> CreateTokenAsync(User user, IList<string> roles)
    {
        var signingCredentials = GetSigningCredentials();
        var claims = GetClaims(user, roles);
        var tokenOptions = GenerateTokenOptions(signingCredentials, claims);
        user.RefreshToken = GenerateRefreshToken();
        user.RefreshTokenExpiresAt = DateTime.UtcNow.AddDays(_jwtSettings.RefreshTokenExpiryInDays);

        await _userManager.UpdateAsync(user);

        return new Token(
            "Bearer",
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
            IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_jwtSettings.SecurityKey))
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
            UserId = await GetUserId(token)
        };

        var accessRecord = new AccessRecord()
        {
            TokenJti = jti,
            IpAddress = ipaddress,
            AccessAt = DateTime.UtcNow,
            UserId = revokedToken.UserId,
            Revoked = true
        };

        await _context.RevokedTokens.AddAsync(revokedToken);
        await _context.AccessRecords.AddAsync(accessRecord);
        await _context.SaveChangesAsync();
    }

    public async Task<bool> IsRevokedAsync(string token)
    {
        var jti = GetJtiFromToken(token);
        return await _context.RevokedTokens.AnyAsync(t => t.TokenJti == jti);
    }

    public async Task AddAccessAttemptAsync(string token, string ipAddress)
    {
        var jti = GetJtiFromToken(token);
        var revokedToken = await _context.RevokedTokens.FindAsync(jti);
        if(revokedToken is null)
        {
            await RevokeTokenAsync(token, ipAddress);
            return;
        }

        var accessRecord = new AccessRecord()
        {
            TokenJti = jti,
            IpAddress = ipAddress,
            AccessAt = DateTime.UtcNow,
            UserId = revokedToken.UserId,
            Revoked = true
        };

        await _context.AccessRecords.AddAsync(accessRecord);
        await _context.SaveChangesAsync();
    }

    public string GetUserName(string token)
    {
        var handler = new JwtSecurityTokenHandler();
        var jwtToken = handler.ReadJwtToken(token);
        var userNameClaim = jwtToken.Claims.FirstOrDefault(c => c.Type == ClaimTypes.Name);

        return userNameClaim?.Value ?? string.Empty;
    }

    private async Task<string> GetUserId(string token)
    {
        var handler = new JwtSecurityTokenHandler();
        var jwtToken = handler.ReadJwtToken(token);
        
        var userIdClaim = jwtToken.Claims.FirstOrDefault(c => c.Type == ClaimTypes.Name);
        if (userIdClaim is null)
        {
            return string.Empty;
        }

        var user = await _userManager.FindByNameAsync(userIdClaim.Value);

        return user?.Id ?? string.Empty;
    }

    private string GetJtiFromToken(string token)
    {
        var tokenHandler = new JwtSecurityTokenHandler();

        var jwtToken = tokenHandler.ReadToken(token) as JwtSecurityToken;
        if (jwtToken == null)
        {
            throw new UnauthorizedAccessException("Invalid token");
        }

        var jti = jwtToken.Claims.FirstOrDefault(claim => claim.Type == JwtRegisteredClaimNames.Jti)?.Value;
        if (jti == null)
        {
            throw new UnauthorizedAccessException("Token does not contain a jti claim");
        }

        return jti;
    }

    private string GenerateRefreshToken()
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
        
        var jwtToken = tokenHandler.ReadToken(token) as JwtSecurityToken;
        if (jwtToken == null)
        {
            return null;
        }

        var expClaim = jwtToken.Claims.FirstOrDefault(claim => claim.Type == JwtRegisteredClaimNames.Exp)?.Value;
        if (expClaim == null)
        {
            return null;
        }

        return DateTimeOffset.FromUnixTimeSeconds(long.Parse(expClaim)).UtcDateTime;
    }

    private SigningCredentials GetSigningCredentials()
    {
        var key = Encoding.UTF8.GetBytes(_jwtSettings.SecurityKey);
        var secret = new SymmetricSecurityKey(key);
        return new SigningCredentials(secret, SecurityAlgorithms.HmacSha256);
    }

    private List<Claim> GetClaims(User user, IList<string> roles)
    {
        var claims = new List<Claim>()
        {
            new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
            new Claim(ClaimTypes.Name, user.UserName!)
        };

        foreach (var role in roles)
        {
            claims.Add(new Claim(ClaimTypes.Role, role));
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
