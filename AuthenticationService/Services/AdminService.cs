using AuthenticationService.Constants;
using AuthenticationService.Entities;
using AuthenticationService.Helpers;
using AuthenticationService.Observability;
using AuthenticationService.Settings;
using AuthenticationService.Shared.Constants;
using AuthenticationService.Shared.Dtos;
using AuthenticationService.Shared.Dtos.Response;
using AuthenticationService.Storage;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using System.Text;
using System.Text.Json;

namespace AuthenticationService.Services;

/// <inheritdoc />
public class AdminService : IAdminService
{
    private static readonly TimeSpan InvitationTokenLifetime = TimeSpan.FromHours(24);

    private readonly DatabaseContext _context;
    private readonly UserManager<User> _userManager;
    private readonly RoleManager<Role> _roleManager;
    private readonly IUserService _userService;
    private readonly ITokenService _tokenService;
    private readonly IEmailService _emailService;
    private readonly PublicUrlSettings _publicUrlSettings;
    private readonly AuthMetrics _metrics;
    private readonly ILogger<AdminService> _logger;

    public AdminService(
        DatabaseContext context,
        UserManager<User> userManager,
        RoleManager<Role> roleManager,
        IUserService userService,
        ITokenService tokenService,
        IEmailService emailService,
        IOptions<PublicUrlSettings> publicUrlSettings,
        AuthMetrics metrics,
        ILogger<AdminService> logger)
    {
        _context = context;
        _userManager = userManager;
        _roleManager = roleManager;
        _userService = userService;
        _tokenService = tokenService;
        _emailService = emailService;
        _publicUrlSettings = publicUrlSettings.Value;
        _metrics = metrics;
        _logger = logger;
    }

    // ------------------------------------------------------------------
    // Read endpoints
    // ------------------------------------------------------------------

    public async Task<PagedResponse<UserSummaryDto>> ListUsersAsync(AdminListFilter filter, CancellationToken ct)
    {
        var page = Math.Max(1, filter.Page);
        var pageSize = Math.Clamp(filter.PageSize, 1, AdminListFilter.MaxPageSize);
        var now = DateTimeOffset.UtcNow;

        IQueryable<User> query = _context.Users.AsNoTracking();

        if (!string.IsNullOrWhiteSpace(filter.Search))
        {
            var s = filter.Search.Trim();
            // Leading-wildcard LIKE — accepts a full scan; admin-list traffic is low.
            query = query.Where(u =>
                (u.UserName != null && EF.Functions.Like(u.UserName, $"%{s}%")) ||
                (u.Email != null && EF.Functions.Like(u.Email, $"%{s}%")));
        }

        if (filter.LockedOnly)
        {
            query = query.Where(u => u.LockoutEnd > now);
        }

        if (filter.UnconfirmedOnly)
        {
            query = query.Where(u => !u.EmailConfirmed);
        }

        var totalCount = await query.CountAsync(ct);

        var results = await query
            .OrderByDescending(u => u.CreatedAt)
            .Skip((page - 1) * pageSize)
            .Take(pageSize)
            .Select(u => new UserSummaryDto
            {
                Id = u.Id,
                UserName = u.UserName ?? string.Empty,
                Email = u.Email ?? string.Empty,
                EmailConfirmed = u.EmailConfirmed,
                IsLocked = u.LockoutEnd > now,
                MfaEnabled = u.TwoFactorEnabled,
                CreatedAt = u.CreatedAt,
            })
            .ToListAsync(ct);

        return new PagedResponse<UserSummaryDto>
        {
            Results = results,
            TotalCount = totalCount,
            Page = page,
            PageSize = pageSize,
        };
    }

    public async Task<UserDetailDto?> GetUserDetailAsync(string id, CancellationToken ct)
    {
        var user = await _userManager.FindByIdAsync(id);
        if (user is null)
        {
            return null;
        }

        var roles = await _userManager.GetRolesAsync(user);
        var now = DateTimeOffset.UtcNow;

        // Proxies "how many devices is this user signed in on right now."
        var activeFamilies = await _context.RefreshTokens
            .AsNoTracking()
            .Where(t => t.UserId == user.Id && t.ConsumedAt == null && t.ExpiresAt > now)
            .Select(t => t.FamilyId)
            .Distinct()
            .CountAsync(ct);

        return new UserDetailDto
        {
            Id = user.Id,
            UserName = user.UserName ?? string.Empty,
            Email = user.Email ?? string.Empty,
            EmailConfirmed = user.EmailConfirmed,
            FirstName = user.FirstName,
            LastName = user.LastName,
            DateOfBirth = user.DateOfBirth,
            PhoneNumber = user.PhoneNumber,
            PhoneNumberConfirmed = user.PhoneNumberConfirmed,
            Country = user.Country,
            AddressLine1 = user.AddressLine1,
            AddressLine2 = user.AddressLine2,
            AddressLine3 = user.AddressLine3,
            City = user.City,
            Postcode = user.Postcode,
            Lockout = BuildLockoutInfo(user),
            Mfa = new MfaInfoDto
            {
                Enabled = user.TwoFactorEnabled,
                PreferredProvider = user.PreferredMfaProvider,
            },
            Roles = roles,
            ActiveRefreshTokenFamilies = activeFamilies,
            CreatedAt = user.CreatedAt,
        };
    }

    // ------------------------------------------------------------------
    // Invitation flow
    // ------------------------------------------------------------------

    public async Task<AdminCreateUserResult> CreateUserAsync(
        AdminCreateUserDto request,
        string adminUserId,
        string ipAddress,
        CancellationToken ct)
    {
        // Empty roles default to DefaultUser. Admin is rejected — admins are only created via DB seed.
        var roles = (request.Roles is { Count: > 0 } ? request.Roles : new List<string> { RolesConstants.DefaultUser }).ToList();
        if (roles.Contains(RolesConstants.Admin, StringComparer.Ordinal))
        {
            return new AdminCreateUserResult.ValidationFailed(new Dictionary<string, string>
            {
                ["roles"] = "Admin role cannot be assigned via the invitation endpoint."
            });
        }

        foreach (var role in roles)
        {
            if (!await _roleManager.RoleExistsAsync(role))
            {
                return new AdminCreateUserResult.UnknownRole(role);
            }
        }

        if (await _userManager.FindByEmailAsync(request.Email!) is not null)
        {
            return new AdminCreateUserResult.Conflict("A user with this email address already exists.");
        }
        if (await _userManager.FindByNameAsync(request.UserName!) is not null)
        {
            return new AdminCreateUserResult.Conflict("A user with this username already exists.");
        }

        var user = new User
        {
            UserName = request.UserName,
            Email = request.Email,
            FirstName = request.FirstName,
            LastName = request.LastName,
            PhoneNumber = request.PhoneNumber,
            DateOfBirth = request.DateOfBirth,
            Country = request.Country,
            AddressLine1 = request.AddressLine1,
            AddressLine2 = request.AddressLine2,
            AddressLine3 = request.AddressLine3,
            City = request.City,
            Postcode = request.Postcode,
            EmailConfirmed = false,
            // PreferredMfaProvider left at default (Email) — user can change via /me once active.
        };

        var createResult = await _userService.CreateAsync(user);
        if (!createResult.Succeeded)
        {
            return new AdminCreateUserResult.IdentityFailed(createResult.Errors);
        }

        var roleResult = await _userManager.AddToRolesAsync(user, roles);
        if (!roleResult.Succeeded)
        {
            // Roll back the user — leaving them with no role is worse than no user.
            await _userManager.DeleteAsync(user);
            return new AdminCreateUserResult.IdentityFailed(roleResult.Errors);
        }

        await SendInvitationEmailAsync(user, request.CallbackUri);

        _logger.LogInformation(
            SecurityEventIds.AdminCreatedUser,
            "Admin {AdminUserId} created user {TargetUserId} with roles {Roles} from {IpAddress}",
            adminUserId,
            user.Id,
            string.Join(",", roles),
            ipAddress);

        return new AdminCreateUserResult.Success(user.Id);
    }

    public async Task<AdminInvitationResendResult> ResendInvitationAsync(
        string targetUserId,
        string adminUserId,
        string ipAddress,
        CancellationToken ct)
    {
        var user = await _userManager.FindByIdAsync(targetUserId);
        if (user is null)
        {
            return AdminInvitationResendResult.UserNotFound;
        }

        // Pending-invitation state = email not confirmed AND no password set.
        if (user.EmailConfirmed || !string.IsNullOrEmpty(user.PasswordHash))
        {
            return AdminInvitationResendResult.UserAlreadyActive;
        }

        await SendInvitationEmailAsync(user, callbackUri: null);

        _logger.LogInformation(
            SecurityEventIds.AdminResentInvitation,
            "Admin {AdminUserId} re-sent invitation to {TargetUserId} from {IpAddress}",
            adminUserId,
            user.Id,
            ipAddress);

        return AdminInvitationResendResult.Resent;
    }

    private async Task SendInvitationEmailAsync(User user, string? callbackUri)
    {
        var rawToken = await _userManager.GeneratePasswordResetTokenAsync(user);
        var encodedToken = WebEncoders.Base64UrlEncode(Encoding.UTF8.GetBytes(rawToken));

        var query = new Dictionary<string, string?>
        {
            [UriConstants.Email] = user.Email,
            [UriConstants.Token] = encodedToken,
        };
        if (!string.IsNullOrWhiteSpace(callbackUri))
        {
            query["callbackUri"] = callbackUri;
        }

        var invitationUri = QueryHelpers.AddQueryString(
            $"{_publicUrlSettings.BaseUrl}{PageRouteConstants.AcceptInvitation}",
            query);

        await _emailService.SendEmailAsync(
            user.Email!,
            EmailSubjects.AccountInvitation,
            $"An administrator has created an account for you. To activate your account and set your password, please click the following link: {invitationUri}. " +
            $"This link will expire in {InvitationTokenLifetime.TotalHours:F0} hours. " +
            "If you weren't expecting this invitation, you can safely ignore this email.");
    }

    // ------------------------------------------------------------------
    // State-changing endpoints
    // ------------------------------------------------------------------

    public async Task<LockoutInfoDto?> LockUserAsync(
        string targetUserId,
        string adminUserId,
        string ipAddress,
        CancellationToken ct)
    {
        var user = await _userManager.FindByIdAsync(targetUserId);
        if (user is null)
        {
            return null;
        }

        await _userManager.SetLockoutEnabledAsync(user, true);
        await _userManager.SetLockoutEndDateAsync(user, LockoutDurations.Indefinite);

        _logger.LogWarning(
            SecurityEventIds.AdminLockedAccount,
            "Admin {AdminUserId} locked account {TargetUserId} from {IpAddress}",
            adminUserId,
            user.Id,
            ipAddress);
        _metrics.LockoutTriggered("admin");

        return BuildLockoutInfo(user);
    }

    public async Task<LockoutInfoDto?> UnlockUserAsync(
        string targetUserId,
        string adminUserId,
        string ipAddress,
        CancellationToken ct)
    {
        var user = await _userManager.FindByIdAsync(targetUserId);
        if (user is null)
        {
            return null;
        }

        user.LockoutEnd = null;
        user.AccessFailedCount = 0;
        await _userManager.UpdateAsync(user);

        _logger.LogInformation(
            SecurityEventIds.AdminUnlockedAccount,
            "Admin {AdminUserId} unlocked account {TargetUserId} from {IpAddress}",
            adminUserId,
            user.Id,
            ipAddress);

        return BuildLockoutInfo(user);
    }

    public async Task<bool> RevokeSessionsAsync(
        string targetUserId,
        string adminUserId,
        string ipAddress,
        CancellationToken ct)
    {
        var user = await _userManager.FindByIdAsync(targetUserId);
        if (user is null)
        {
            return false;
        }

        // No access token to revoke — this is the admin's call, not the target's. Family
        // revocation + stamp rotation kill the target's tokens on next refresh.
        await _userService.InvalidateUserTokensAsync(user, ipAddress, RevocationReasons.AdminRevokedSessions);

        _logger.LogWarning(
            SecurityEventIds.AdminRevokedSessions,
            "Admin {AdminUserId} revoked all sessions for {TargetUserId} from {IpAddress}",
            adminUserId,
            user.Id,
            ipAddress);

        return true;
    }

    public async Task<bool> ResetMfaAsync(
        string targetUserId,
        string adminUserId,
        string ipAddress,
        CancellationToken ct)
    {
        var user = await _userManager.FindByIdAsync(targetUserId);
        if (user is null)
        {
            return false;
        }

        await _userManager.SetTwoFactorEnabledAsync(user, false);
        await _userManager.ResetAuthenticatorKeyAsync(user);

        // If MFA was the last barrier behind a stolen password, leaving live sessions undoes the protection.
        await _userService.InvalidateUserTokensAsync(user, ipAddress, RevocationReasons.AdminResetMfa);

        _logger.LogWarning(
            SecurityEventIds.AdminResetMfa,
            "Admin {AdminUserId} reset MFA for {TargetUserId} from {IpAddress}",
            adminUserId,
            user.Id,
            ipAddress);

        return true;
    }

    public async Task<bool> ForcePasswordResetAsync(
        string targetUserId,
        string adminUserId,
        string ipAddress,
        string? callbackUri,
        CancellationToken ct)
    {
        var user = await _userManager.FindByIdAsync(targetUserId);
        if (user is null)
        {
            return false;
        }

        // Generate the reset token BEFORE any stamp rotation — InvalidateUserTokensAsync
        // would invalidate the token we're about to email. The landed semantics:
        //   - Refresh tokens revoked now (user can't refresh past current access-token expiry).
        //   - Outstanding access tokens ride out their natural lifetime (≤5 min default) —
        //     they're stamp-validated only in the refresh flow.
        //   - Completing the reset rotates the stamp as a side effect, killing remaining tokens.
        var rawToken = await _userManager.GeneratePasswordResetTokenAsync(user);
        var encodedToken = WebEncoders.Base64UrlEncode(Encoding.UTF8.GetBytes(rawToken));

        var resetCallback = string.IsNullOrWhiteSpace(callbackUri)
            ? $"{_publicUrlSettings.BaseUrl}{PageRouteConstants.ResetPassword}"
            : callbackUri;
        var resetUri = AccountHelpers.GenerateResetPasswordUri(user.Email!, encodedToken, resetCallback);

        await _emailService.SendEmailAsync(
            user.Email!,
            EmailSubjects.PasswordReset,
            $"An administrator has initiated a password reset on your account. " +
            $"To set a new password, click the following link: {resetUri}. " +
            "If you didn't expect this, please contact your administrator.");

        // Refresh-token revocation only — no stamp rotation (see above).
        await _tokenService.RevokeAllRefreshTokenFamiliesAsync(user.Id, RevocationReasons.AdminForcedPasswordReset);

        _logger.LogWarning(
            SecurityEventIds.AdminForcedPasswordReset,
            "Admin {AdminUserId} forced password reset for {TargetUserId} from {IpAddress}",
            adminUserId,
            user.Id,
            ipAddress);

        return true;
    }

    // ------------------------------------------------------------------
    // Audit
    // ------------------------------------------------------------------

    public async Task<PagedResponse<AuditEntryDto>?> GetAuditAsync(AdminAuditFilter filter, CancellationToken ct)
    {
        // 404 vs. empty page — don't make a non-existent user look like "no activity".
        var userExists = await _context.Users.AsNoTracking().AnyAsync(u => u.Id == filter.UserId, ct);
        if (!userExists)
        {
            return null;
        }

        var page = Math.Max(1, filter.Page);
        var pageSize = Math.Clamp(filter.PageSize, 1, AdminAuditFilter.MaxPageSize);
        // Last 30 days by default — bounds the query for users with long histories.
        var since = filter.Since ?? DateTimeOffset.UtcNow.AddDays(-30);

        var query = _context.SecurityEvents
            .AsNoTracking()
            .Where(e => e.UserId == filter.UserId && e.Timestamp >= since);

        if (filter.EventId is { } eid)
        {
            query = query.Where(e => e.EventId == eid);
        }

        var totalCount = await query.CountAsync(ct);

        var rows = await query
            .OrderByDescending(e => e.Timestamp)
            .Skip((page - 1) * pageSize)
            .Take(pageSize)
            .ToListAsync(ct);

        var results = rows.Select(MapAuditEntry).ToList();

        return new PagedResponse<AuditEntryDto>
        {
            Results = results,
            TotalCount = totalCount,
            Page = page,
            PageSize = pageSize,
        };
    }

    private static AuditEntryDto MapAuditEntry(SecurityEvent row)
    {
        var fields = new Dictionary<string, string?>();
        if (!string.IsNullOrEmpty(row.PropertiesJson))
        {
            try
            {
                using var doc = JsonDocument.Parse(row.PropertiesJson);
                foreach (var element in doc.RootElement.EnumerateObject())
                {
                    fields[element.Name] = element.Value.ValueKind == JsonValueKind.Null
                        ? null
                        : element.Value.ToString();
                }
            }
            catch (JsonException)
            {
                // Shouldn't happen — we wrote it. Surface raw text rather than dropping the row.
                fields["_raw"] = row.PropertiesJson;
            }
        }

        return new AuditEntryDto
        {
            Timestamp = row.Timestamp,
            EventId = row.EventId,
            EventName = row.EventName,
            IpAddress = row.IpAddress,
            Severity = row.Level,
            Fields = fields,
        };
    }

    // ------------------------------------------------------------------
    // Helpers
    // ------------------------------------------------------------------

    private static LockoutInfoDto BuildLockoutInfo(User user)
    {
        var now = DateTimeOffset.UtcNow;
        return new LockoutInfoDto
        {
            IsLocked = user.LockoutEnd != null && user.LockoutEnd > now,
            LockoutEnd = user.LockoutEnd,
            AccessFailedCount = user.AccessFailedCount,
            LockoutEnabled = user.LockoutEnabled,
        };
    }
}
