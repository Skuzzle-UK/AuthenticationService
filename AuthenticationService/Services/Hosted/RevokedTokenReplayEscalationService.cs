using AuthenticationService.Constants;
using AuthenticationService.Entities;
using AuthenticationService.Helpers;
using AuthenticationService.Observability;
using AuthenticationService.Settings;
using AuthenticationService.Storage;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using System.Text;

namespace AuthenticationService.Services.Hosted;

/// <summary>
/// Watches <c>RevokedTokenAccessAttempts</c> for sustained replay of revoked tokens.
/// Warn threshold emits a SIEM event; lock threshold locks the account indefinitely, revokes
/// every refresh-token family, and emails the user a recovery link.
/// Idempotency via <c>WarnedAt</c> / <c>LockedAt</c> columns — each incident fires once.
/// See <see cref="ThresholdEscalationSettings"/> for tuning.
/// </summary>
public class RevokedTokenReplayEscalationService : BackgroundService
{
    private readonly ILogger<RevokedTokenReplayEscalationService> _logger;
    private readonly IServiceScopeFactory _serviceScopeFactory;
    private readonly ThresholdEscalationSettings _settings;
    private readonly PublicUrlSettings _publicUrlSettings;
    private readonly AuthMetrics _metrics;

    public RevokedTokenReplayEscalationService(
        ILogger<RevokedTokenReplayEscalationService> logger,
        IServiceScopeFactory serviceScopeFactory,
        IOptions<ThresholdEscalationSettings> settings,
        IOptions<PublicUrlSettings> publicUrlSettings,
        AuthMetrics metrics)
    {
        _logger = logger;
        _serviceScopeFactory = serviceScopeFactory;
        _settings = settings.Value;
        _publicUrlSettings = publicUrlSettings.Value;
        _metrics = metrics;
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

    // Internal so tests can drive escalation without the timer loop.
    internal async Task RunSweepAsync(CancellationToken stoppingToken)
    {
        using var scope = _serviceScopeFactory.CreateScope();
        var context = scope.ServiceProvider.GetRequiredService<DatabaseContext>();
        var userService = scope.ServiceProvider.GetRequiredService<IUserService>();
        var tokenService = scope.ServiceProvider.GetRequiredService<ITokenService>();
        var emailService = scope.ServiceProvider.GetRequiredService<IEmailService>();

        var windowStart = DateTime.UtcNow.AddMinutes(-_settings.WindowInMinutes);

        // Group by jti in the window — table is bounded by cleanup so this is small.
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

        // One-row-at-a-time lookup instead of a batched Contains query: Oracle's
        // MySql.EntityFrameworkCore can't translate Contains-on-collection. N is single-digit
        // in practice. Revert to a batched query once we move to Pomelo.
        foreach (var attempt in attemptCounts)
        {
            var revokedToken = await context.RevokedTokens
                .FirstOrDefaultAsync(t => t.TokenJti == attempt.Jti, stoppingToken);

            if (revokedToken is null)
            {
                // Audit row points at a jti we don't have — shouldn't happen, skip gracefully.
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
            
            _metrics.ThresholdEscalationFired("warned");

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
            // User deleted out of band — nothing to lock. Live requests are handled by the
            // controllers' orphan-token defence.
            _logger.LogWarning(
                "Cannot lock account for {UserId} jti {Jti} — user not found.",
                revokedToken.UserId,
                revokedToken.TokenJti);
            return;
        }

        // Indefinite lock — forgot-password flow clears LockoutEnd on success.
        await userService.SetLockoutEndDateAsync(user, LockoutDurations.Indefinite);

        // If one session is compromised, treat all as suspect — same cascade as reuse-detected.
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
       
        _metrics.ThresholdEscalationFired("locked"); 
        _metrics.LockoutTriggered("threshold_escalation");
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
            // Include a reset link so the user can recover without a "forgot password" UI affordance.
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
            // Don't let email failure block the lock — the security action already happened.
            _logger.LogError(
                ex,
                "Failed to send lock-notification email to {UserId}: {ErrorMsg}",
                user.Id,
                ex.Message);
        }
    }
}
