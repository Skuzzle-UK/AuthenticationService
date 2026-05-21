using AuthenticationService.Constants;
using AuthenticationService.Entities;
using AuthenticationService.Enums;
using AuthenticationService.Observability;
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

/// <summary>
/// Default <see cref="ITokenService"/>. Owns JWT signing, refresh-token hashing and rotation
/// with reuse detection, the revoked-token deny-list, and the replay audit trail. Hits the DB
/// directly via <see cref="DatabaseContext"/> rather than going through Identity.
/// </summary>
public class JWTService : ITokenService
{
    private readonly JWTSettings _jwtSettings;
    private readonly ClientCredentialsSettings _clientCredentialsSettings;
    private readonly UserManager<User> _userManager;
    private readonly DatabaseContext _context;
    private readonly IEcdsaKeyProvider _keyProvider;
    private readonly ILogger<JWTService> _logger;
    private readonly AuthMetrics _metrics;

    private static readonly JwtSecurityTokenHandler TokenHandler = new();

    public JWTService(
        IOptions<JWTSettings> jwtSettings,
        IOptions<ClientCredentialsSettings> clientCredentialsSettings,
        UserManager<User> userManager,
        DatabaseContext context,
        IEcdsaKeyProvider keyProvider,
        ILogger<JWTService> logger,
        AuthMetrics metrics)
    {
        _jwtSettings = jwtSettings.Value;
        _clientCredentialsSettings = clientCredentialsSettings.Value;
        _userManager = userManager;
        _context = context;
        _keyProvider = keyProvider;
        _logger = logger;
        _metrics = metrics;
    }

    public async Task<Token> CreateTokenAsync(
        User user,
        IList<string> roles,
        Guid? familyId = null,
        string? ipAddress = null,
        Guid? refreshTokenId = null)
    {
        var family = familyId ?? Guid.NewGuid();
        var rawRefreshToken = GenerateRefreshToken();

        var refreshTokenEntity = new RefreshToken
        {
            // Rotation supplies a pre-allocated Id so it can stamp the predecessor's
            // ReplacedByTokenId atomically. Other callers get a fresh Guid here.
            Id = refreshTokenId ?? Guid.NewGuid(),
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

        return new Token
        {
            Type = AuthSchemeConstants.Bearer,
            Value = TokenHandler.WriteToken(tokenOptions),
            Expires = tokenOptions.ValidTo,
            RefreshToken = rawRefreshToken,
            RefreshTokenExpiresAt = refreshTokenEntity.ExpiresAt,
        };
    }

    public Task<Token> CreateServiceTokenAsync(string clientId, string audience, IEnumerable<string> scopes)
    {
        var scopeList = scopes.ToList();
        var expiresAt = DateTime.UtcNow.AddHours(_clientCredentialsSettings.TokenLifetimeInHours);

        var claims = new List<Claim>
        {
            // sub = client_id by design — consumers distinguish service tokens by absent
            // email/sid claims AND by sub being a client_id rather than a user id.
            new(ClaimConstants.Sub, clientId),
            new(ClaimConstants.ClientId, clientId),
            new(ClaimConstants.Azp, clientId),
            new(ClaimConstants.Jti, Guid.NewGuid().ToString()),
            // Space-separated per OAuth convention.
            new(ClaimConstants.Scope, string.Join(' ', scopeList)),
        };

        var tokenOptions = new JwtSecurityToken(
            issuer: _jwtSettings.ValidIssuer,
            audience: audience,
            claims: claims,
            expires: expiresAt,
            signingCredentials: _keyProvider.SigningCredentials);

        // No refresh half — service tokens re-authenticate from scratch.
        return Task.FromResult(new Token
        {
            Type = AuthSchemeConstants.Bearer,
            Value = TokenHandler.WriteToken(tokenOptions),
            Expires = expiresAt,
            RefreshToken = null,
            RefreshTokenExpiresAt = null,
        });
    }

    public async Task<RefreshResult> RotateRefreshTokenAsync(string accessToken, string rawRefreshToken, string ipAddress)
    {
        // Manual transaction has to run inside CreateExecutionStrategy so the retry
        // strategy can retry the whole thing as one unit on transient DB failures.
        var strategy = _context.Database.CreateExecutionStrategy();
        return await strategy.ExecuteAsync<RefreshResult>(async () =>
        {
            using var transaction = await _context.Database.BeginTransactionAsync();

            var hash = HashRefreshToken(rawRefreshToken);
            var userId = GetUserId(accessToken);
            if (string.IsNullOrEmpty(userId))
            {
                return new RefreshResult.NotFound();
            }

            // AsNoTracking — the consume step below uses ExecuteUpdateAsync with a WHERE clause
            // for race-resistance rather than going through the change tracker.
            var existing = await _context.RefreshTokens
                .AsNoTracking()
                .FirstOrDefaultAsync(t => t.TokenHash == hash && t.UserId == userId);

            if (existing is null)
            {
                return new RefreshResult.NotFound();
            }

            if (existing.ConsumedAt is not null)
            {
                return await CascadeReuseAsync(userId, existing.FamilyId, transaction);
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

            // Pre-allocate the new PK so we can stamp ReplacedByTokenId atomically with the consume.
            var newTokenId = Guid.NewGuid();

            var rowsClaimed = await _context.RefreshTokens
                .Where(t => t.Id == existing.Id && t.ConsumedAt == null)
                .ExecuteUpdateAsync(s => s
                    .SetProperty(t => t.ConsumedAt, DateTime.UtcNow)
                    .SetProperty(t => t.ReplacedByTokenId, (Guid?)newTokenId));

            if (rowsClaimed == 0)
            {
                return await CascadeReuseAsync(userId, existing.FamilyId, transaction);
            }

            var roles = await _userManager.GetRolesAsync(user);
            var newToken = await CreateTokenAsync(user, roles, existing.FamilyId, ipAddress, newTokenId);

            await transaction.CommitAsync();
            return new RefreshResult.Success(newToken);
        });
    }

    private async Task<RefreshResult> CascadeReuseAsync(
        string userId,
        Guid compromisedFamilyId,
        Microsoft.EntityFrameworkCore.Storage.IDbContextTransaction transaction)
    {
        await RevokeAllRefreshTokenFamiliesAsync(userId, RevocationReasons.ReuseDetected);

        var compromisedUser = await _userManager.FindByIdAsync(userId);
        if (compromisedUser is not null)
        {
            await _userManager.UpdateSecurityStampAsync(compromisedUser);
        }

        await transaction.CommitAsync();
        return new RefreshResult.Reused(compromisedFamilyId);
    }

    public async Task RevokeAllRefreshTokenFamiliesAsync(string userId, string reason)
    {
        var now = DateTime.UtcNow;
        await _context.RefreshTokens
            .Where(t => t.UserId == userId && t.ConsumedAt == null)
            .ExecuteUpdateAsync(s => s
                .SetProperty(t => t.ConsumedAt, now)
                .SetProperty(t => t.RevocationReason, reason));
    }

    public async Task RevokeFamilyAsync(Guid familyId, string reason)
    {
        var now = DateTime.UtcNow;
        await _context.RefreshTokens
            .Where(t => t.FamilyId == familyId && t.ConsumedAt == null)
            .ExecuteUpdateAsync(s => s
                .SetProperty(t => t.ConsumedAt, now)
                .SetProperty(t => t.RevocationReason, reason));
    }

    private static string HashRefreshToken(string rawToken)
    {
        var bytes = Encoding.UTF8.GetBytes(rawToken);
        var hash = SHA256.HashData(bytes);
        return Convert.ToBase64String(hash);
    }

    public async Task<bool> ValidateExpiredTokenAsync(string token)
    {
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

        var validationResult = await TokenHandler.ValidateTokenAsync(token, parameters);
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
        
        _metrics.TokenRevoked(reason);
    }

    public async Task<RevokedToken?> GetRevokedTokenAsync(string token)
    {
        var jti = GetJtiFromToken(token);
        return await _context.RevokedTokens.FindAsync(jti);
    }

    public async Task RevokeOrphanedTokenAsync(string token, string ipAddress)
    {
        await RevokeTokenAsync(token, ipAddress, RevocationReasons.UserNotFound);

        _logger.LogWarning(
            SecurityEventIds.OrphanedTokenRevoked,
            "Orphaned token revoked for {UserId} from {IpAddress} — token referenced a user that no longer exists",
            GetUserId(token),
            ipAddress);
    }

    public async Task RecordRevokedReplayAsync(RevokedToken revokedToken, string ipAddress, string? userAgent)
    {
        // Still-live revoked token = Medium (only the deny-list stops it);
        // naturally-expired revoked token = Low (JwtBearer's expiry check would reject anyway).
        var severity = revokedToken.ExpiresAt.HasValue && revokedToken.ExpiresAt.Value < DateTime.UtcNow
            ? Severity.Low
            : Severity.Medium;

        _logger.LogWarning(
            SecurityEventIds.RevokedTokenReplayAttempt,
            "Revoked token replay for {UserId} jti {Jti} from {IpAddress} (severity: {Severity})",
            revokedToken.UserId,
            revokedToken.TokenJti,
            ipAddress,
            severity);
        
        _metrics.RevokedTokenReplayAttempt(severity.ToString());

        var attempt = new RevokedTokenAccessAttempt
        {
            TokenJti = revokedToken.TokenJti,
            UserId = revokedToken.UserId,
            IpAddress = ipAddress,
            UserAgent = TruncateUserAgent(userAgent),
            CreatedAt = DateTime.UtcNow,
            Severity = severity,
        };

        await _context.RevokedTokenAccessAttempts.AddAsync(attempt);
        await _context.SaveChangesAsync();
    }

    // Defends against a malicious 10MB User-Agent bloating the audit table.
    private static string? TruncateUserAgent(string? userAgent)
    {
        if (string.IsNullOrEmpty(userAgent))
        {
            return null;
        }

        const int maxLength = 512;
        return userAgent.Length <= maxLength ? userAgent : userAgent[..maxLength];
    }

    public string GetUserId(string token)
    {
        var jwtToken = TokenHandler.ReadJwtToken(token);
        return jwtToken.Claims.FirstOrDefault(c => c.Type == ClaimConstants.Sub)?.Value ?? string.Empty;
    }

    private static string GetJtiFromToken(string token)
    {
        if (TokenHandler.ReadToken(token) is not JwtSecurityToken jwtToken)
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
        if (TokenHandler.ReadToken(token) is not JwtSecurityToken jwtToken)
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
