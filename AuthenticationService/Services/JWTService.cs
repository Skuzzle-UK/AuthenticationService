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
using System.Text;

namespace AuthenticationService.Services;

public class JWTService : ITokenService
{
    private readonly JWTSettings _jwtSettings;
    private readonly UserManager<User> _userManager;
    private readonly DatabaseContext _context;
    private readonly IEcdsaKeyProvider _keyProvider;
    private readonly ILogger<JWTService> _logger;

    public JWTService(
        IOptions<JWTSettings> jwtSettings,
        UserManager<User> userManager,
        DatabaseContext context,
        IEcdsaKeyProvider keyProvider,
        ILogger<JWTService> logger)
    {
        _jwtSettings = jwtSettings.Value;
        _userManager = userManager;
        _context = context;
        _keyProvider = keyProvider;
        _logger = logger;
    }

    public async Task<Token> CreateTokenAsync(User user, IList<string> roles, Guid? familyId = null, string? ipAddress = null)
    {
        var family = familyId ?? Guid.NewGuid();
        var rawRefreshToken = GenerateRefreshToken();

        var refreshTokenEntity = new RefreshToken
        {
            Id = Guid.NewGuid(),
            UserId = user.Id,
            TokenHash = HashRefreshToken(rawRefreshToken),
            FamilyId = family,
            CreatedAt = DateTime.UtcNow,
            ExpiresAt = DateTime.UtcNow.AddDays(_jwtSettings.RefreshTokenExpiryInDays),
            CreatedFromIp = ipAddress,
        };

        await _context.RefreshTokens.AddAsync(refreshTokenEntity);

        var claims = GetClaims(user, roles, family);
        var tokenOptions = GenerateTokenOptions(_keyProvider.SigningCredentials, claims);

        await _context.SaveChangesAsync();

        return new Token(
            AuthSchemeConstants.Bearer,
            new JwtSecurityTokenHandler().WriteToken(tokenOptions),
            tokenOptions.ValidTo,
            rawRefreshToken,
            refreshTokenEntity.ExpiresAt);
    }

    public async Task<RefreshResult> RotateRefreshTokenAsync(string accessToken, string rawRefreshToken, string ipAddress)
    {
        using var transaction = await _context.Database.BeginTransactionAsync();

        var hash = HashRefreshToken(rawRefreshToken);
        var userId = GetUserId(accessToken);
        if (string.IsNullOrEmpty(userId))
        {
            return new RefreshResult.NotFound();
        }

        var existing = await _context.RefreshTokens
            .FirstOrDefaultAsync(t => t.TokenHash == hash && t.UserId == userId);

        if (existing is null)
        {
            return new RefreshResult.NotFound();
        }

        if (existing.ConsumedAt is not null)
        {
            // Reuse detected. Defensive cascade: revoke every refresh-token family for this
            // user and rotate the security stamp so all outstanding access tokens die too.
            var compromisedFamilyId = existing.FamilyId;
            await RevokeAllRefreshTokenFamiliesAsync(userId, RevocationReasons.ReuseDetected);
            var compromisedUser = await _userManager.FindByIdAsync(userId);
            if (compromisedUser is not null)
            {
                await _userManager.UpdateSecurityStampAsync(compromisedUser);
            }
            await transaction.CommitAsync();
            return new RefreshResult.Reused(compromisedFamilyId);
        }

        if (existing.ExpiresAt < DateTime.UtcNow)
        {
            return new RefreshResult.Expired();
        }

        var user = await _userManager.FindByIdAsync(userId);
        if (user is null)
        {
            return new RefreshResult.NotFound();
        }

        var roles = await _userManager.GetRolesAsync(user);
        var newToken = await CreateTokenAsync(user, roles, existing.FamilyId, ipAddress);

        existing.ConsumedAt = DateTime.UtcNow;

        await _context.SaveChangesAsync();
        await transaction.CommitAsync();

        return new RefreshResult.Success(newToken);
    }

    public async Task RevokeAllRefreshTokenFamiliesAsync(string userId, string reason)
    {
        var activeTokens = await _context.RefreshTokens
            .Where(t => t.UserId == userId && t.ConsumedAt == null)
            .ToListAsync();

        var now = DateTime.UtcNow;
        foreach (var token in activeTokens)
        {
            token.ConsumedAt = now;
            token.RevocationReason = reason;
        }

        await _context.SaveChangesAsync();
    }

    public async Task RevokeFamilyAsync(Guid familyId, string reason)
    {
        var activeTokens = await _context.RefreshTokens
            .Where(t => t.FamilyId == familyId && t.ConsumedAt == null)
            .ToListAsync();

        var now = DateTime.UtcNow;
        foreach (var token in activeTokens)
        {
            token.ConsumedAt = now;
            token.RevocationReason = reason;
        }

        await _context.SaveChangesAsync();
    }

    private static string HashRefreshToken(string rawToken)
    {
        var bytes = Encoding.UTF8.GetBytes(rawToken);
        var hash = SHA256.HashData(bytes);
        return Convert.ToBase64String(hash);
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
            IssuerSigningKeys = _keyProvider.PublicSecurityKeys,
            ValidAlgorithms = [SecurityAlgorithms.EcdsaSha256]
        };

        var validationResult = await tokenHandler.ValidateTokenAsync(token, parameters);
        return validationResult.IsValid;
    }

    public async Task RevokeTokenAsync(string token, string ipAddress, string reason)
    {
        var jti = GetJtiFromToken(token);
        var userId = GetUserId(token);

        var revokedToken = new RevokedToken()
        {
            TokenJti = jti,
            ExpiresAt = GetExpiryDateTime(token),
            UserId = userId,
            RevokedFromIp = ipAddress,
            RevokedAt = DateTime.UtcNow,
            RevocationReason = reason,
        };

        await _context.RevokedTokens.AddAsync(revokedToken);
        await _context.SaveChangesAsync();

        _logger.LogInformation(
            SecurityEventIds.TokenRevoked,
            "Access token {Jti} revoked for {UserId} from {IpAddress} ({Reason})",
            jti,
            userId,
            ipAddress,
            reason);
    }

    public async Task<bool> IsRevokedAsync(string token)
    {
        var jti = GetJtiFromToken(token);
        return await _context.RevokedTokens.AnyAsync(t => t.TokenJti == jti);
    }

    public async Task RecordAccessAttemptAsync(string token, string ipAddress)
    {
        var jti = GetJtiFromToken(token);
        var userId = GetUserId(token);
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

        if (isRevoked)
        {
            _logger.LogWarning(
                SecurityEventIds.RevokedTokenReplayAttempt,
                "Revoked token replay for {UserId} jti {Jti} from {IpAddress} (severity: {Severity})",
                userId,
                jti,
                ipAddress,
                severity);
        }

        var accessRecord = new AccessRecord()
        {
            TokenJti = jti,
            IpAddress = ipAddress,
            CreatedAt = DateTime.UtcNow,
            UserId = userId,
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
            throw new UnauthorizedAccessException(ErrorMessages.InvalidToken);
        }

        var jti = jwtToken.Claims.FirstOrDefault(claim => claim.Type == ClaimConstants.Jti)?.Value;
        
        return jti
            ?? throw new UnauthorizedAccessException(ErrorMessages.MissingJtiClaim);
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

    private static List<Claim> GetClaims(User user, IList<string> roles, Guid familyId)
    {
        var claims = new List<Claim>()
        {
            new(ClaimConstants.Sub, user.Id),
            new(ClaimConstants.Sid, familyId.ToString()),
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
