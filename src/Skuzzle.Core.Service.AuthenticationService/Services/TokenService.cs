using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using Skuzzle.Core.Service.AuthenticationService.Models;
using Skuzzle.Core.Service.AuthenticationService.Settings;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;

namespace Skuzzle.Core.Service.AuthenticationService.Services;

public class TokenService : ITokenService
{
    private readonly string _securityKey;
    private readonly string _issuer;
    private readonly string _audience;

    public TokenService(IOptions<JwtSettings> settings)
    {
        _securityKey = settings.Value.Key;
        _issuer = settings.Value.Issuer;
        _audience = settings.Value.Audience;
    }

    public string GetNewToken(User user)
    {
        //TODO: Add a tonne of claims
        List<Claim> claims = new List<Claim>()
        {
            new Claim(ClaimTypes.Name, user.Username),
            new Claim(ClaimTypes.Role, string.Join(",", user.Roles))
        };

        var key = new SymmetricSecurityKey(System.Text.Encoding.UTF8.GetBytes(_securityKey));

        var cred = new SigningCredentials(key, SecurityAlgorithms.HmacSha512Signature);

        var token = new JwtSecurityToken(
            claims: claims,
            expires: DateTime.UtcNow.AddDays(1),
            signingCredentials: cred,
            issuer: _issuer,
            audience: _audience);

        return new JwtSecurityTokenHandler().WriteToken(token);
    }
}
