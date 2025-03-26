using AuthenticationService.Entities;
using AuthenticationService.Settings;
using AuthenticationService.Shared.Models;
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

    public JWTService(IOptions<JWTSettings> jwtSettings)
    {
        _jwtSettings = jwtSettings.Value;
    }

    public Token CreateToken(User user, IList<string> roles)
    {
        var signingCredentials = GetSigningCredentials();
        var claims = GetClaims(user, roles);
        var tokenOptions = GenerateTokenOptions(signingCredentials, claims);

        return new Token(
            "Bearer",
            new JwtSecurityTokenHandler().WriteToken(tokenOptions),
            tokenOptions.ValidTo);
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
            expires: DateTime.UtcNow.AddMinutes(Convert.ToDouble(_jwtSettings.ExpiryInMinutes)),
            signingCredentials: signingCredentials);

        return tokenOptions;
    }
}
