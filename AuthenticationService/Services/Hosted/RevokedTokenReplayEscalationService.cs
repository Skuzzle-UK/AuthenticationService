using AuthenticationService.Constants;
using AuthenticationService.Entities;
using AuthenticationService.Helpers;
using AuthenticationService.Settings;
using AuthenticationService.Storage;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using System.Text;

namespace AuthenticationService.Services.Hosted;

/// <summary>
/// Watches the <c>RevokedTokenAccessAttempts</c> audit table for sustained replay of
/// already-revoked access tokens. Two thresholds, both evaluated within a sliding window:
/// <list type="bullet">
///   <item><description><b>Warn threshold</b> — emits <see cref="SecurityEventIds.RevokedTokenReplayThresholdWarned"/> for SIEM. No user-facing impact.</description></item>
///   <item><description><b>Lock threshold</b> — locks the account indefinitely (<see cref="DateTimeOffset.MaxValue"/>), revokes every refresh-token family for the user, emails the user a recovery link, and emits <see cref="SecurityEventIds.RevokedTokenReplayThresholdLocked"/>.</description></item>
/// </list>
///
/// <para>Idempotency is via two nullable columns on <see cref="RevokedToken"/>
/// (<c>WarnedAt</c>, <c>LockedAt</c>) — once an incident has been warned/locked we stamp
/// the column and don't re-fire on subsequent sweeps. If the attacker keeps replaying
/// after the lock, the middleware keeps writing audit rows but this service does nothing
/// further (the account is already locked, the user already knows).</para>
///
/// <para>Defaults are aggressive (warn on the second replay, lock on the fifth, within a
/// 5-min window). See <see cref="ThresholdEscalationSettings"/> for tuning.</para>
/// </summary>
public class RevokedTokenReplayEscalationService : BackgroundService
{
    private readonly ILogger<RevokedTokenReplayEscalationService> _logger;
    private readonly IServiceScopeFactory _serviceScopeFactory;
    private readonly ThresholdEscalationSettings _settings;
    private readonly PublicUrlSettings _publicUrlSettings;

    public RevokedTokenReplayEscalationService(
        ILogger<RevokedTokenReplayEscalationService> logger,
        IServiceScopeFactory serviceScopeFactory,
        IOptions<ThresholdEscalationSettings> settings,
        IOptions<PublicUrlSettings> publicUrlSettings)
    {
        _logger = logger;
        _serviceScopeFactory = serviceScopeFactory;
        _settings = settings.Value;
        _publicUrlSettings = publicUrlSettings.Value;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        if (!_settings.Enabled)
        {
            _logger.LogInformation(
                "Revoked-token replay escalation service is disabled via configuration; not running.");
            return;
        }

        _logger.LogInformation(
            "Revoked-token replay escalation service started. Window {WindowMinutes} min, " +
            "warn at {WarnThreshold} replays, lock at {LockThreshold} replays, sweep every {SweepIntervalMinutes} min.",
            _settings.WindowInMinutes,
            _settings.WarnThreshold,
            _settings.LockThreshold,
            _settings.SweepIntervalInMinutes);

        using var timer = new PeriodicTimer(TimeSpan.FromMinutes(_settings.SweepIntervalInMinutes));

        try
        {
            await RunSweepAsync(stoppingToken);
            while (await timer.WaitForNextTickAsync(stoppingToken))
            {
                await RunSweepAsync(stoppingToken);
            }
        }
        catch (OperationCanceledException)
        {
            // Expected during shutdown.
            _logger.LogInformation("Revoked-token replay escalation service cancellation requested.");
        }
        catch (Exception ex)
        {
            _logger.LogError(
                ex,
                "Revoked-token replay escalation service terminated unexpectedly: {ErrorMsg}",
                ex.Message);
        }
        finally
        {
            _logger.LogInformation("Revoked-token replay escalation service stopped.");
        }
    }

    /// <summary>
    /// One pass of the sweep. Exposed as <c>internal</c> so tests can drive escalation
    /// logic directly without going through <see cref="ExecuteAsync"/>'s timer loop.
    /// </summary>
    internal async Task RunSweepAsync(CancellationToken stoppingToken)
    {
        using var scope = _serviceScopeFactory.CreateScope();
        var context = scope.ServiceProvider.GetRequiredService<DatabaseContext>();
        var userService = scope.ServiceProvider.GetRequiredService<IUserService>();
        var tokenService = scope.ServiceProvider.GetRequiredService<ITokenService>();
        var emailService = scope.ServiceProvider.GetRequiredService<IEmailService>();

        var windowStart = DateTime.UtcNow.AddMinutes(-_settings.WindowInMinutes);

        // Group attempts by jti within the window. Pulling the jti + count back to memory
        // is fine — even at high-volume replay rates we're talking thousands of rows max
        // (cleanup keeps the table bounded), not millions.
        var attemptCounts = await context.RevokedTokenAccessAttempts
            .Where(a => a.CreatedAt >= windowStart)
            .GroupBy(a => a.TokenJti)
            .Select(g => new { Jti = g.Key, Count = g.Count() })
            .Where(g => g.Count >= _settings.WarnThreshold)
            .ToListAsync(stoppingToken);

        if (attemptCounts.Count == 0)
        {
            return;
        }

        // Load every revoked-token row we might need to update in one round-trip.
        var jtis = attemptCounts.Select(a => a.Jti).ToList();
        var revokedTokens = await context.RevokedTokens
            .Where(t => jtis.Contains(t.TokenJti))
            .ToDictionaryAsync(t => t.TokenJti, stoppingToken);

        foreach (var attempt in attemptCounts)
        {
            if (!revokedTokens.TryGetValue(attempt.Jti, out var revokedToken))
            {
                // Audit row references a jti we don't have a revocation row for. Should
                // not happen under normal flows but skip gracefully.
                continue;
            }

            await EscalateAsync(revokedToken, attempt.Count, context, userService, tokenService, emailService, stoppingToken);
        }

        await context.SaveChangesAsync(stoppingToken);
    }

    private async Task EscalateAsync(
        RevokedToken revokedToken,
        int attemptCount,
        DatabaseContext context,
        IUserService userService,
        ITokenService tokenService,
        IEmailService emailService,
        CancellationToken stoppingToken)
    {
        // Warn level — once per incident.
        if (revokedToken.WarnedAt is null && attemptCount >= _settings.WarnThreshold)
        {
            _logger.LogWarning(
                SecurityEventIds.RevokedTokenReplayThresholdWarned,
                "Revoked-token replay warn threshold crossed for {UserId} jti {Jti}: {AttemptCount} replays in last {WindowMinutes} min",
                revokedToken.UserId,
                revokedToken.TokenJti,
                attemptCount,
                _settings.WindowInMinutes);

            revokedToken.WarnedAt = DateTime.UtcNow;
        }

        // Lock level — once per incident.
        if (revokedToken.LockedAt is null && attemptCount >= _settings.LockThreshold)
        {
            await ApplyLockAsync(revokedToken, attemptCount, userService, tokenService, emailService, stoppingToken);
            revokedToken.LockedAt = DateTime.UtcNow;
        }
    }

    private async Task ApplyLockAsync(
        RevokedToken revokedToken,
        int attemptCount,
        IUserService userService,
        ITokenService tokenService,
        IEmailService emailService,
        CancellationToken stoppingToken)
    {
        var user = await userService.FindByIdAsync(revokedToken.UserId);
        if (user is null)
        {
            // User behind the revoked token is gone (deleted out of band). The
            // orphan-token defence in the controllers handles this case for live
            // requests. For escalation, just log and move on — there's nothing to
            // lock.
            _logger.LogWarning(
                "Cannot lock account for {UserId} jti {Jti} — user not found.",
                revokedToken.UserId,
                revokedToken.TokenJti);
            return;
        }

        // Indefinite lock — same shape as the panic-button /lock endpoint. The user's
        // forgot-password flow is the recovery path and clears LockoutEnd on success.
        await userService.SetLockoutEndDateAsync(user, DateTimeOffset.MaxValue);

        // Treat every other live token for this user as suspect. Same defensive cascade
        // as the refresh-token reuse-detected path — if one session is compromised, all
        // are.
        await tokenService.RevokeAllRefreshTokenFamiliesAsync(user.Id, RevocationReasons.ReuseDetected);
        await userService.UpdateSecurityStampAsync(user);

        await SendLockNotificationEmailAsync(user, attemptCount, userService, emailService);

        _logger.LogCritical(
            SecurityEventIds.RevokedTokenReplayThresholdLocked,
            "Revoked-token replay lock threshold crossed for {UserId} jti {Jti}: {AttemptCount} replays in last {WindowMinutes} min — account locked",
            revokedToken.UserId,
            revokedToken.TokenJti,
            attemptCount,
            _settings.WindowInMinutes);
    }

    private async Task SendLockNotificationEmailAsync(
        User user,
        int attemptCount,
        IUserService userService,
        IEmailService emailService)
    {
        if (string.IsNullOrEmpty(user.Email))
        {
            return;
        }

        try
        {
            // Generate a reset-password token + link so the user can recover even if
            // their UI doesn't have a "forgot password" affordance built. Same pattern
            // as the existing forgot-password and panic-lock flows.
            var resetToken = await userService.GeneratePasswordResetTokenAsync(user);
            var encodedToken = WebEncoders.Base64UrlEncode(Encoding.UTF8.GetBytes(resetToken));
            var resetUri = AccountHelpers.GenerateResetPasswordUri(
                user.Email,
                encodedToken,
                $"{_publicUrlSettings.BaseUrl}{PageRouteConstants.ResetPassword}");

            await emailService.SendEmailAsync(
                user.Email,
                EmailSubjects.SuspiciousActivity,
                $"We detected repeated use of an expired session token from your account ({attemptCount} attempts in the last few minutes). " +
                "As a precaution, your account has been locked and every active session signed out. " +
                $"To regain access, set a new password using this link: {resetUri}. " +
                "If you didn't realise your session was compromised, change your password on every device and review recent activity once you're back in.");
        }
        catch (Exception ex)
        {
            // Email send failure shouldn't prevent the lock from taking effect — the
            // important security action (locking + revoking) has already happened by
            // the time we get here.
            _logger.LogError(
                ex,
                "Failed to send lock-notification email to {UserId}: {ErrorMsg}",
                user.Id,
                ex.Message);
        }
    }
}
