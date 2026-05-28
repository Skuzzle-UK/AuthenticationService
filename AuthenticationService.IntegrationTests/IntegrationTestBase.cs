using System.Net.Http.Json;
using Aspire.Hosting.Testing;
using AuthenticationService.Shared.Dtos;
using AuthenticationService.Shared.Dtos.Response;
using AuthenticationService.Shared.Models;
using AuthenticationService.Storage;
using Microsoft.EntityFrameworkCore;

namespace AuthenticationService.IntegrationTests;

/// <summary>
/// Base class for integration tests that join <see cref="IntegrationTestCollection"/>.
/// Provides ready-made <see cref="HttpClient"/>s for the auth service and smtp4dev, and
/// clears the smtp4dev inbox at the start of every test.
/// </summary>
public abstract class IntegrationTestBase(AppHostFixture fixture) : IAsyncLifetime
{
    protected AppHostFixture Fixture { get; } = fixture;

    protected HttpClient AuthClient { get; private set; } = default!;

    protected Smtp4DevClient SmtpClient { get; private set; } = default!;

    public virtual async Task InitializeAsync()
    {
        AuthClient = Fixture.App.CreateHttpClient("auth", "http");
        var smtpHttp = Fixture.App.CreateHttpClient("smtp4dev", "http");
        SmtpClient = new Smtp4DevClient(smtpHttp);

        // Tests share one smtp4dev across the run; clearing per-test keeps email
        // assertions from picking up leftovers from earlier tests.
        await SmtpClient.ClearAsync();
    }

    public virtual Task DisposeAsync()
    {
        AuthClient?.Dispose();
        return Task.CompletedTask;
    }

    /// <summary>
    /// Email unique to this test run — avoids collisions on the shared MySQL.
    /// </summary>
    protected static string UniqueEmail() => $"test-{Guid.NewGuid():N}@example.com";

    /// <summary>
    /// Username unique to this test run.
    /// </summary>
    protected static string UniqueUserName() => $"user-{Guid.NewGuid():N}";

    /// <summary>
    /// Identity for a user the test created and confirmed.
    /// </summary>
    public sealed record ConfirmedUser(string Email, string Password, string UserName);

    /// <summary>
    /// Runs the full register-then-confirm flow and returns the credentials. Duplicates
    /// Scenario 1's flow on purpose — that scenario asserts the flow; this just uses it.
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
    /// on failure or MFA-required — tests that need MFA do it inline.
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
    /// Returns a <see cref="DatabaseContext"/> connected to the same DB the auth service
    /// uses (connection string resolved via Aspire's resource graph, not
    /// <c>appsettings.json</c>). Provider is picked from <see cref="AppHostFixture.DbProvider"/>
    /// so the same helper works under the CI matrix and the in-process quirks suite.
    /// Caller owns disposal — use <c>await using</c>.
    /// </summary>
    protected async Task<DatabaseContext> CreateDbContextAsync()
    {
        var connectionString = await ResolveConnectionStringAsync();
        var builder = new DbContextOptionsBuilder<DatabaseContext>();
        ConfigureDbContextProvider(builder, connectionString);
        return new DatabaseContext(builder.Options);
    }

    /// <summary>
    /// Resolves the active DB connection string from Aspire's resource graph.
    /// </summary>
    protected async Task<string> ResolveConnectionStringAsync() =>
        await Fixture.App.GetConnectionStringAsync("AuthenticationService")
            ?? throw new InvalidOperationException(
                "Aspire didn't expose a connection string for the 'AuthenticationService' database.");

    /// <summary>
    /// Applies the EF provider matching <see cref="AppHostFixture.DbProvider"/> to the
    /// supplied builder. Use in test-owned <c>AddDbContext</c> registrations so the same
    /// test code adapts under MySQL / SqlServer / PostgreSQL without conditional logic
    /// at each call site.
    /// </summary>
    protected void ConfigureDbContextProvider(DbContextOptionsBuilder builder, string connectionString)
    {
        switch (Fixture.DbProvider)
        {
            case "MySQL":
                builder.UseMySQL(connectionString);
                break;
            case "SqlServer":
                builder.UseSqlServer(connectionString);
                break;
            case "PostgreSQL":
                builder.UseNpgsql(connectionString);
                break;
            default:
                throw new InvalidOperationException(
                    $"Unknown DbProvider '{Fixture.DbProvider}' — can't pick an EF provider.");
        }
    }
}
