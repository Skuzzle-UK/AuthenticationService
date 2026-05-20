using AuthenticationService.Shared.Dtos.Response;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using NSubstitute;
using System.Net;
using System.Net.Http.Json;
using System.Text.Json;

namespace AuthenticationService.TokenClientLib.Tests.Helpers;

/// <summary>
/// Convenience builders for setting up <see cref="ServiceTokenProvider"/> instances
/// against a <see cref="StubHttpMessageHandler"/>. Keeps the per-test arrange blocks
/// to the few lines that actually differ between tests.
/// </summary>
internal static class TestProviderBuilder
{
    public const string DefaultAuthority = "https://auth.example.test";
    public const string DefaultTokenEndpoint = "https://auth.example.test/oauth/token";

    /// <summary>
    /// Builds a provider whose <see cref="IHttpClientFactory"/> returns a fresh
    /// <see cref="HttpClient"/> wrapping <paramref name="stub"/> on each call.
    /// The <c>HttpClient</c> is constructed with <c>disposeHandler: false</c> so the
    /// provider's <c>using</c> blocks don't drop the shared stub.
    /// </summary>
    public static ServiceTokenProvider Build(
        StubHttpMessageHandler stub,
        ServiceTokenClientOptions? options = null)
    {
        options ??= new ServiceTokenClientOptions
        {
            Authority = DefaultAuthority,
            ClientId = "test-client",
            ClientSecret = "test-secret",
            TokenEndpointOverride = DefaultTokenEndpoint,
            MaxRetriesOnTransient = 0,
        };

        var factory = Substitute.For<IHttpClientFactory>();
        factory
            .CreateClient(ServiceTokenProvider.HttpClientName)
            .Returns(_ => new HttpClient(stub, disposeHandler: false));

        return new ServiceTokenProvider(
            factory,
            Options.Create(options),
            NullLogger<ServiceTokenProvider>.Instance);
    }

    /// <summary>
    /// Returns a 200 OK response carrying an <c>OAuthTokenResponse</c> JSON body.
    /// Default <paramref name="expiresIn"/> is a comfortable hour so cache logic
    /// has somewhere to bite; pass <c>-1</c> (or any non-positive value) to make
    /// the resulting <c>CachedToken.IsValid()</c> return false immediately.
    /// </summary>
    public static HttpResponseMessage TokenOk(string accessToken, int expiresIn = 3600, string scope = "scope.x") =>
        new(HttpStatusCode.OK)
        {
            Content = JsonContent.Create(new OAuthTokenResponse
            {
                AccessToken = accessToken,
                ExpiresIn = expiresIn,
                Scope = scope,
                TokenType = "Bearer",
            }),
        };

    /// <summary>
    /// Returns an OAuth-shaped error response (RFC 6749 §5.2) — body carries
    /// <c>{ error, error_description }</c>. Default status is 400.
    /// </summary>
    public static HttpResponseMessage OAuthError(string error, string? description = null, HttpStatusCode status = HttpStatusCode.BadRequest)
    {
        // Build the JSON by hand because OAuthErrorResponse is internal to the
        // TokenClientLib project; the wire shape is well-known.
        var payload = JsonSerializer.Serialize(new Dictionary<string, string?>
        {
            ["error"] = error,
            ["error_description"] = description,
        });
        return new HttpResponseMessage(status)
        {
            Content = new StringContent(payload, System.Text.Encoding.UTF8, "application/json"),
        };
    }

    /// <summary>Returns an empty response with the given status — useful for transient-failure scripts.</summary>
    public static HttpResponseMessage Status(HttpStatusCode status) => new(status);

    /// <summary>
    /// Polls <paramref name="condition"/> until it returns true or the timeout elapses.
    /// Used for asserting fire-and-forget background work (e.g. proactive refresh)
    /// without sleeping for an entire pessimistic budget.
    /// </summary>
    public static async Task WaitUntilAsync(Func<bool> condition, TimeSpan? timeout = null, TimeSpan? pollInterval = null)
    {
        var hardLimit = timeout ?? TimeSpan.FromSeconds(2);
        var poll = pollInterval ?? TimeSpan.FromMilliseconds(10);
        var deadline = DateTimeOffset.UtcNow + hardLimit;
        while (DateTimeOffset.UtcNow < deadline)
        {
            if (condition()) return;
            await Task.Delay(poll);
        }
        if (!condition())
        {
            throw new TimeoutException($"Condition not met within {hardLimit}.");
        }
    }
}
