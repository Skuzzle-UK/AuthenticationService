using System.Net.Http.Json;
using Aspire.Hosting.Testing;
using AuthenticationService.Shared.Dtos;
using AuthenticationService.Shared.Dtos.Response;
using AuthenticationService.Shared.Models;
using AuthenticationService.Storage;
using Microsoft.EntityFrameworkCore;

namespace AuthenticationService.IntegrationTests;

/// <summary>
/// Base class for integration test classes that join <see cref="IntegrationTestCollection"/>.
/// Provides ready-made <see cref="HttpClient"/>s for the auth service and smtp4dev's
/// API, and clears the smtp4dev inbox at the start of every test so assertions never
/// see stale messages from earlier tests.
/// </summary>
public abstract class IntegrationTestBase(AppHostFixture fixture) : IAsyncLifetime
{
    protected AppHostFixture Fixture { get; } = fixture;

    /// <summary>HttpClient pointed at the auth service's https endpoint.</summary>
    protected HttpClient AuthClient { get; private set; } = default!;

    /// <summary>Wrapped client for smtp4dev's HTTP API.</summary>
    protected Smtp4DevClient SmtpClient { get; private set; } = default!;

    public virtual async Task InitializeAsync()
    {
        AuthClient = Fixture.App.CreateHttpClient("auth", "http");
        var smtpHttp = Fixture.App.CreateHttpClient("smtp4dev", "http");
        SmtpClient = new Smtp4DevClient(smtpHttp);

        // Tests share one MySQL + one smtp4dev across the whole run for speed. The
        // tradeoff is tests must isolate themselves — emails from prior tests would be
        // confusable with the current one. Clearing the inbox per-test makes the
        // "find this email" assertions reliable without coordinating across tests.
        await SmtpClient.ClearAsync();
    }

    public virtual Task DisposeAsync()
    {
        AuthClient?.Dispose();
        return Task.CompletedTask;
    }

    /// <summary>
    /// Generates an email address unique to this test run. Tests use this for the
    /// user they create so they don't collide with other tests using the same shared
    /// MySQL.
    /// </summary>
    protected static string UniqueEmail() => $"test-{Guid.NewGuid():N}@example.com";

    /// <summary>
    /// Username unique to this test run — same isolation argument as
    /// <see cref="UniqueEmail"/>.
    /// </summary>
    protected static string UniqueUserName() => $"user-{Guid.NewGuid():N}";

    /// <summary>
    /// Identity for a user the test created and confirmed. Carries the credentials so
    /// later steps in the same test can log in as them, and the email so DB queries
    /// can locate them.
    /// </summary>
    public sealed record ConfirmedUser(string Email, string Password, string UserName);

    /// <summary>
    /// Goes through the full register-then-confirm dance and returns the credentials.
    /// Most scenarios start with "have a confirmed user" — this saves them re-doing the
    /// dance every time. Implementation-wise it duplicates Scenario 1's flow on purpose:
    /// Scenario 1 is the assertion that the flow works; this helper is just a builder
    /// that uses the (now-trusted) flow.
    /// </summary>
    protected async Task<ConfirmedUser> RegisterAndConfirmUserAsync(string? password = null)
    {
        var email = UniqueEmail();
        var resolvedPassword = password ?? "P@ssw0rd1234";
        var userName = UniqueUserName();

        var registration = new RegistrationDto
        {
            UserName = userName,
            DateOfBirth = new DateOnly(1990, 1, 1),
            Email = email,
            Password = resolvedPassword,
            ConfirmPassword = resolvedPassword,
        };

        var registerResponse = await AuthClient.PostAsJsonAsync("/api/Registration/register", registration);
        registerResponse.EnsureSuccessStatusCode();

        var message = await SmtpClient.WaitForMessageAsync(email, TimeSpan.FromSeconds(10))
            ?? throw new InvalidOperationException(
                $"No confirmation email arrived for {email} within 10s.");

        var body = await SmtpClient.GetMessageHtmlAsync(message.Id);
        var link = MailLinkExtractor.FindLinkContaining(body, "/api/registration/confirm/email")
            ?? throw new InvalidOperationException(
                "Confirmation email body didn't contain the expected confirm-email link.");

        var confirmResponse = await AuthClient.GetAsync(link);
        confirmResponse.EnsureSuccessStatusCode();

        return new ConfirmedUser(email, resolvedPassword, userName);
    }

    /// <summary>
    /// Logs in as the supplied user and returns the issued <see cref="Token"/>. Throws
    /// if the login fails or returns an MFA-required response (the helper is for
    /// non-MFA flows; tests that need MFA do it inline).
    /// </summary>
    protected async Task<Token> LoginAsync(ConfirmedUser user)
    {
        var response = await AuthClient.PostAsJsonAsync(
            "/api/Authentication/authenticate",
            new AuthenticationDto { Email = user.Email, Password = user.Password });
        response.EnsureSuccessStatusCode();

        var auth = await response.Content.ReadFromJsonAsync<AuthenticationResponse>()
            ?? throw new InvalidOperationException("Login response body deserialised to null.");

        if (auth.MfaRequired == true || auth.Token is null)
        {
            throw new InvalidOperationException(
                "Login required MFA — use a non-MFA test account, or do the login inline.");
        }

        return auth.Token;
    }

    /// <summary>
    /// Returns a <see cref="DatabaseContext"/> connected to the same MySQL instance the
    /// auth service is using. Used by tests that need to assert directly on persisted
    /// state (e.g., "the old refresh token row is consumed"). The connection string is
    /// resolved through Aspire's resource graph so the test always points at the
    /// runtime-allocated MySQL, not whatever's in <c>appsettings.json</c>.
    ///
    /// <para>Caller owns disposal — use <c>await using</c>.</para>
    /// </summary>
    protected async Task<DatabaseContext> CreateDbContextAsync()
    {
        var connectionString = await Fixture.App.GetConnectionStringAsync("AuthenticationService")
            ?? throw new InvalidOperationException(
                "Aspire didn't expose a connection string for the 'AuthenticationService' database.");

        var options = new DbContextOptionsBuilder<DatabaseContext>()
            .UseMySQL(connectionString)
            .Options;

        return new DatabaseContext(options);
    }
}
