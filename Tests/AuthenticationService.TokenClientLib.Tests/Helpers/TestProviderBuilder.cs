using AuthenticationService.Shared.Dtos.Response;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using NSubstitute;
using System.Net;
using System.Net.Http.Json;
using System.Text.Json;

namespace AuthenticationService.TokenClientLib.Tests.Helpers;

/// <summary>
/// Convenience builders for ServiceTokenProvider instances against a StubHttpMessageHandler.
/// </summary>
internal static class TestProviderBuilder
{
    public const string DefaultAuthority = "https://auth.example.test";
    public const string DefaultTokenEndpoint = "https://auth.example.test/oauth/token";

    /// <summary>
    /// Builds a provider whose IHttpClientFactory returns fresh HttpClients wrapping
    /// <paramref name="stub"/>. <c>disposeHandler: false</c> so the provider's using
    /// blocks don't drop the shared stub.
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
    /// 200 OK response with an OAuthTokenResponse JSON body. Pass <paramref name="expiresIn"/>
    /// non-positive to force <c>CachedToken.IsValid()</c> false immediately.
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
    /// OAuth-shaped error response (RFC 6749 §5.2) — body carries <c>{ error, error_description }</c>.
    /// </summary>
    public static HttpResponseMessage OAuthError(string error, string? description = null, HttpStatusCode status = HttpStatusCode.BadRequest)
    {
        // Build JSON by hand — OAuthErrorResponse is internal to TokenClientLib.
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

    /// <summary>
    /// Returns an empty response with the given status — useful for transient-failure scripts.
    /// </summary>
    public static HttpResponseMessage Status(HttpStatusCode status) => new(status);

    /// <summary>
    /// Polls until <paramref name="condition"/> is true or the timeout elapses. Used for
    /// asserting fire-and-forget background work without sleeping the pessimistic budget.
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
