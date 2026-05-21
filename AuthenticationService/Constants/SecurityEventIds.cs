namespace AuthenticationService.Constants;

/// <summary>
/// Stable <see cref="EventId"/>s for security events. SIEM rules match on these IDs — treat
/// them as a wire contract, values must not change once deployed.
///
/// <para>Property conventions: PascalCase names, same name = same meaning across every event.
/// <c>UserId</c> (sub claim), <c>IpAddress</c>, <c>Jti</c>, <c>FamilyId</c> (sid claim),
/// <c>Reason</c>, <c>Provider</c>, <c>Severity</c>. Email / passwords / token values /
/// authenticator secrets MUST NOT appear in payloads — use <c>UserId</c> for correlation.</para>
///
/// <para>Ranges: 1000s authentication, 2000s registration, 3000s account, 4000s token,
/// 5000s admin, 6000s s2s.</para>
/// </summary>
public static class SecurityEventIds
{
    // ------------------------------------------------------------------
    // 1000s — Authentication
    // ------------------------------------------------------------------

    /// <summary>
    /// A user successfully authenticated and was issued a token pair.
    /// </summary>
    public static readonly EventId LoginSucceeded = new(1001, nameof(LoginSucceeded));

    /// <summary>
    /// A login attempt failed. Reason carried in the <c>{Reason}</c> field (bad credentials, email not confirmed, account locked, etc.).
    /// </summary>
    public static readonly EventId LoginFailed = new(1002, nameof(LoginFailed));

    /// <summary>
    /// An MFA challenge was issued to the user — code emailed / generated in the authenticator app.
    /// </summary>
    public static readonly EventId MfaChallengeIssued = new(1003, nameof(MfaChallengeIssued));

    /// <summary>
    /// The user submitted a valid MFA code; login completed.
    /// </summary>
    public static readonly EventId MfaVerified = new(1004, nameof(MfaVerified));

    /// <summary>
    /// The user submitted an invalid MFA code. Counts toward the failed-login lockout the same as a wrong password.
    /// </summary>
    public static readonly EventId MfaFailed = new(1005, nameof(MfaFailed));

    /// <summary>
    /// An account was auto-locked after exceeding the configured failed-attempt threshold.
    /// </summary>
    public static readonly EventId FailedLoginLockoutTriggered = new(1006, nameof(FailedLoginLockoutTriggered));

    /// <summary>
    /// A refresh token was successfully rotated; the caller received a new access + refresh pair.
    /// </summary>
    public static readonly EventId RefreshTokenRotated = new(1007, nameof(RefreshTokenRotated));

    /// <summary>
    /// An already-consumed refresh token was presented again. Treated as theft — every active session for the user is revoked. <b>Critical level</b> — page on every occurrence.
    /// </summary>
    public static readonly EventId RefreshTokenReuseDetected = new(1008, nameof(RefreshTokenReuseDetected));

    /// <summary>
    /// The user logged out of a single device (single refresh-token family revoked).
    /// </summary>
    public static readonly EventId LogoutPerDevice = new(1009, nameof(LogoutPerDevice));

    /// <summary>
    /// The user logged out of every device (every refresh-token family revoked, security stamp rotated).
    /// </summary>
    public static readonly EventId LogoutAllDevices = new(1010, nameof(LogoutAllDevices));

    // ------------------------------------------------------------------
    // 2000s — Registration
    // ------------------------------------------------------------------

    /// <summary>
    /// A new user account was created.
    /// </summary>
    public static readonly EventId RegistrationCompleted = new(2001, nameof(RegistrationCompleted));

    /// <summary>
    /// The user clicked the confirmation link in their registration email; their email is now confirmed.
    /// </summary>
    public static readonly EventId EmailConfirmed = new(2002, nameof(EmailConfirmed));

    /// <summary>
    /// The user clicked an email-confirmation link but the token didn't validate (wrong, expired, or for a different user).
    /// </summary>
    public static readonly EventId EmailConfirmationFailed = new(2003, nameof(EmailConfirmationFailed));

    /// <summary>
    /// An admin-invited user clicked their invitation link and set their initial password.
    /// Account is now active (email confirmed + password hash present) and ready to log in.
    /// </summary>
    public static readonly EventId InvitationAccepted = new(2004, nameof(InvitationAccepted));

    // ------------------------------------------------------------------
    // 3000s — Account management
    // ------------------------------------------------------------------

    /// <summary>
    /// The user changed their password while authenticated.
    /// </summary>
    public static readonly EventId PasswordChanged = new(3001, nameof(PasswordChanged));

    /// <summary>
    /// The user kicked off the "I forgot my password" flow; we emailed them a reset link.
    /// </summary>
    public static readonly EventId PasswordResetRequested = new(3002, nameof(PasswordResetRequested));

    /// <summary>
    /// The user completed the reset flow — supplied a valid reset token and set a new password.
    /// </summary>
    public static readonly EventId PasswordResetCompleted = new(3003, nameof(PasswordResetCompleted));

    /// <summary>
    /// The user clicked the panic-button "wasn't me!" link in a password-changed email; their account is now locked.
    /// </summary>
    public static readonly EventId AccountLockedByUser = new(3004, nameof(AccountLockedByUser));

    /// <summary>
    /// The user enabled MFA on their account. Provider in the <c>{Provider}</c> field.
    /// </summary>
    public static readonly EventId MfaEnabled = new(3005, nameof(MfaEnabled));

    /// <summary>
    /// The user updated their profile (name, address, phone, etc.). Phone-number changes
    /// reset the phone-confirmed flag — track which fields changed via the <c>{Fields}</c>
    /// payload field if forensic detail is needed.
    /// </summary>
    public static readonly EventId ProfileUpdated = new(3006, nameof(ProfileUpdated));

    // ------------------------------------------------------------------
    // 4000s — Token state
    // ------------------------------------------------------------------

    /// <summary>
    /// An access token was added to the deny-list. Reason in the <c>{Reason}</c> field.
    /// </summary>
    public static readonly EventId TokenRevoked = new(4001, nameof(TokenRevoked));

    /// <summary>
    /// An already-revoked access token was presented again. <c>{Severity}</c> field distinguishes "still-live" replay (Medium) from "naturally-expired" replay (Low).
    /// </summary>
    public static readonly EventId RevokedTokenReplayAttempt = new(4002, nameof(RevokedTokenReplayAttempt));

    /// <summary>
    /// An access token was revoked because the user it referenced no longer exists in the database. Defensive — closes the door on a token that's signed correctly but no longer represents a real user.
    /// </summary>
    public static readonly EventId OrphanedTokenRevoked = new(4003, nameof(OrphanedTokenRevoked));

    /// <summary>
    /// The threshold-escalation worker spotted repeated replay of a single revoked token and emitted a warn-level signal. No user-facing impact.
    /// </summary>
    public static readonly EventId RevokedTokenReplayThresholdWarned = new(4004, nameof(RevokedTokenReplayThresholdWarned));

    /// <summary>
    /// The threshold-escalation worker locked an account due to sustained replay of a revoked token. Account is now indefinitely locked; user must reset password to recover. <b>Critical level</b> — page on every occurrence.
    /// </summary>
    public static readonly EventId RevokedTokenReplayThresholdLocked = new(4005, nameof(RevokedTokenReplayThresholdLocked));

    // ------------------------------------------------------------------
    // 5000s — Admin actions
    //
    // All admin events log {AdminUserId} (the actor) and {TargetUserId} (who they
    // acted on) so SIEM can group by either dimension and answer "what did this
    // admin do?" / "what's been done to this user?" independently.
    // ------------------------------------------------------------------

    /// <summary>
    /// An admin manually locked a user account (indefinite lockout).
    /// </summary>
    public static readonly EventId AdminLockedAccount = new(5001, nameof(AdminLockedAccount));

    /// <summary>
    /// An admin lifted an active lockout and reset the failed-attempt counter.
    /// </summary>
    public static readonly EventId AdminUnlockedAccount = new(5002, nameof(AdminUnlockedAccount));

    /// <summary>
    /// An admin revoked all refresh-token families for a user and rotated the security stamp ("sign out everywhere" hammer).
    /// </summary>
    public static readonly EventId AdminRevokedSessions = new(5003, nameof(AdminRevokedSessions));

    /// <summary>
    /// An admin cleared a user's MFA configuration (typically helpdesk handling a lost-phone case). Sessions are revoked implicitly.
    /// </summary>
    public static readonly EventId AdminResetMfa = new(5004, nameof(AdminResetMfa));

    /// <summary>
    /// An admin triggered a password reset on a user — a reset email goes to the user and existing sessions are revoked.
    /// </summary>
    public static readonly EventId AdminForcedPasswordReset = new(5005, nameof(AdminForcedPasswordReset));

    /// <summary>
    /// An admin created a new user via the invite flow. <c>EmailConfirmed</c> is false and no password is set until the user clicks the invitation link.
    /// </summary>
    public static readonly EventId AdminCreatedUser = new(5006, nameof(AdminCreatedUser));

    /// <summary>
    /// An admin re-sent the invitation email for a user who never clicked their original link (still in pending-invitation state).
    /// </summary>
    public static readonly EventId AdminResentInvitation = new(5007, nameof(AdminResentInvitation));

    /// <summary>
    /// Break-glass admin-account recovery ran (CLI subcommand or <c>ResetOnStartup</c>
    /// flag). Password reset from <c>AdminAccountSeedSettings:Password</c>, lockout cleared,
    /// MFA disabled, refresh tokens revoked, security stamp rotated. <b>Critical level</b> —
    /// page on every occurrence; this should be a rare, deliberate operator action.
    /// </summary>
    public static readonly EventId AdminAccountRecovered = new(5100, nameof(AdminAccountRecovered));

    // ------------------------------------------------------------------
    // 6000s — Service-to-service auth (OAuth client-credentials grant)
    //
    // Token-endpoint events log {ClientId}, {Audience}, {Scopes}, {IpAddress}.
    // Client-management events log {AdminUserId}, {ClientId}, {IpAddress}.
    // ------------------------------------------------------------------

    /// <summary>
    /// A client successfully exchanged credentials at <c>/oauth/token</c> and was issued a service-identity JWT.
    /// </summary>
    public static readonly EventId ClientCredentialsTokenIssued = new(6001, nameof(ClientCredentialsTokenIssued));

    /// <summary>
    /// A token-endpoint request was rejected. Reason in <c>{Reason}</c> (invalid_client / invalid_scope / unsupported_grant_type / invalid_request).
    /// </summary>
    public static readonly EventId ClientCredentialsTokenDenied = new(6002, nameof(ClientCredentialsTokenDenied));

    /// <summary>
    /// An admin created a new s2s client via <c>POST /api/Admin/clients</c>. The plaintext secret is shown to the admin in the response (one-time display); only the hash is persisted.
    /// </summary>
    public static readonly EventId AdminCreatedClient = new(6101, nameof(AdminCreatedClient));

    /// <summary>
    /// An admin rotated a client's secret. The previous hash is overwritten; the new plaintext is shown once in the response.
    /// </summary>
    public static readonly EventId AdminRotatedClientSecret = new(6102, nameof(AdminRotatedClientSecret));

    /// <summary>
    /// An admin soft-disabled a client. Subsequent <c>/oauth/token</c> attempts return <c>invalid_client</c>; the row stays for audit / re-enable.
    /// </summary>
    public static readonly EventId AdminDisabledClient = new(6103, nameof(AdminDisabledClient));

    /// <summary>
    /// An admin added a (audience, scope) tuple to a client's scope list.
    /// </summary>
    public static readonly EventId AdminAddedClientScope = new(6104, nameof(AdminAddedClientScope));

    /// <summary>
    /// An admin removed a (audience, scope) tuple from a client's scope list.
    /// </summary>
    public static readonly EventId AdminRemovedClientScope = new(6105, nameof(AdminRemovedClientScope));
}