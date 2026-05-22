using AuthenticationService.TokenClientLib.Tests.Helpers;
using AwesomeAssertions;
using System.Net;
using System.Net.Http.Json;

namespace AuthenticationService.TokenClientLib.Tests;

/// <summary>
/// Pins the behavioural contract in docs/service-token-client-plan.md — cache, refresh,
/// discovery, retry. HTTP driven by StubHttpMessageHandler; proactive-refresh tests use
/// real Task.Delay since the path needs wall-clock time.
/// </summary>
public class ServiceTokenProviderTests
{
    // ─── Happy path ───────────────────────────────────────────────────────────────

    [Fact]
    public async Task GetTokenAsync_FirstCall_FetchesViaHttpAndReturnsAccessToken()
    {
        // arrange — TokenEndpointOverride skips discovery so we assert on exactly one HTTP hit.
        var stub = new StubHttpMessageHandler
        {
            Responder = _ => TestProviderBuilder.TokenOk("jwt-aaa"),
        };
        var provider = TestProviderBuilder.Build(stub);

        // act
        var token = await provider.GetTokenAsync("inventory-api", new[] { "inventory.read" });

        // assert
        token.Should().Be("jwt-aaa");
        stub.CountRequestsContaining("/oauth/token").Should().Be(1);
    }

    [Fact]
    public async Task GetTokenAsync_TokenRequest_UsesBasicAuthAndClientCredentialsBody()
    {
        // arrange — capture the request body from INSIDE the responder; the provider's `using` block
        // disposes the request before the test resumes, so reading Content afterwards
        // would throw ObjectDisposedException.
        string? capturedBody = null;
        string? capturedAuthScheme = null;
        HttpMethod? capturedMethod = null;
        var stub = new StubHttpMessageHandler
        {
            Responder = req =>
            {
                capturedMethod = req.Method;
                capturedAuthScheme = req.Headers.Authorization?.Scheme;
                // Read synchronously to capture before the provider disposes the request.
                capturedBody = req.Content!.ReadAsStringAsync().GetAwaiter().GetResult();
                return TestProviderBuilder.TokenOk("jwt-x");
            },
        };
        var provider = TestProviderBuilder.Build(stub);

        // act
        await provider.GetTokenAsync("inventory-api", new[] { "inventory.read", "inventory.write" });

        // assert
        capturedMethod.Should().Be(HttpMethod.Post);
        capturedAuthScheme.Should().Be("Basic");
        capturedBody.Should().Contain("grant_type=client_credentials");
        capturedBody.Should().Contain("audience=inventory-api");
        // Form-encoded space is '+'.
        capturedBody.Should().Contain("scope=inventory.read+inventory.write");
    }

    // ─── Cache ────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task GetTokenAsync_SecondCallWithinLifetime_ReturnsCachedToken()
    {
        // arrange
        var stub = new StubHttpMessageHandler();
        stub.ResponseQueue.Enqueue(TestProviderBuilder.TokenOk("jwt-once", expiresIn: 3600));
        var provider = TestProviderBuilder.Build(stub);

        // act
        var first = await provider.GetTokenAsync("inventory-api", new[] { "inventory.read" });
        var second = await provider.GetTokenAsync("inventory-api", new[] { "inventory.read" });

        // assert
        second.Should().Be(first);
        stub.CountRequestsContaining("/oauth/token").Should().Be(1);
    }

    [Fact]
    public async Task GetTokenAsync_PastExpiry_BlocksOnRefreshAndReturnsNewToken()
    {
        // arrange — expires_in=-1 forces IsValid() false on the next call → slow refresh path.
        var stub = new StubHttpMessageHandler();
        stub.ResponseQueue.Enqueue(TestProviderBuilder.TokenOk("jwt-old", expiresIn: -1));
        stub.ResponseQueue.Enqueue(TestProviderBuilder.TokenOk("jwt-new", expiresIn: 3600));
        var provider = TestProviderBuilder.Build(stub);

        // act
        var first = await provider.GetTokenAsync("aud", new[] { "read" });
        var second = await provider.GetTokenAsync("aud", new[] { "read" });

        // assert
        first.Should().Be("jwt-old");
        second.Should().Be("jwt-new");
        stub.CountRequestsContaining("/oauth/token").Should().Be(2);
    }

    [Fact]
    public async Task GetTokenAsync_PastProactiveThreshold_ReturnsCurrentAndRefreshesInBackground()
    {
        // arrange — RefreshAtFractionOfLifetime=0.0 → refresh threshold == issuedAt, so the second
        // call sees the cached token as valid AND past the proactive threshold (returns
        // cached + fires fire-and-forget refresh).
        var stub = new StubHttpMessageHandler();
        stub.ResponseQueue.Enqueue(TestProviderBuilder.TokenOk("jwt-current", expiresIn: 3600));
        stub.ResponseQueue.Enqueue(TestProviderBuilder.TokenOk("jwt-refreshed", expiresIn: 3600));
        var options = new ServiceTokenClientOptions
        {
            Authority = TestProviderBuilder.DefaultAuthority,
            ClientId = "test-client",
            ClientSecret = "test-secret",
            TokenEndpointOverride = TestProviderBuilder.DefaultTokenEndpoint,
            RefreshAtFractionOfLifetime = 0.0,
            MaxRetriesOnTransient = 0,
        };
        var provider = TestProviderBuilder.Build(stub, options);

        // act
        var first = await provider.GetTokenAsync("aud", new[] { "read" });
        var second = await provider.GetTokenAsync("aud", new[] { "read" });

        // assert
        first.Should().Be("jwt-current");
        second.Should().Be("jwt-current",
            because: "the user-facing call should never block on the background refresh — that's the whole point of the proactive window.");

        // Wait with a timeout so a fast machine doesn't race past the assert and a stuck
        // one doesn't hang the suite.
        await TestProviderBuilder.WaitUntilAsync(() => stub.CountRequestsContaining("/oauth/token") == 2);

        // Cached token swapped — third call returns the new value with no extra HTTP.
        var third = await provider.GetTokenAsync("aud", new[] { "read" });
        third.Should().Be("jwt-refreshed");
        stub.CountRequestsContaining("/oauth/token").Should().Be(2,
            because: "the third call hits the freshly-refreshed cache; nothing else should fire.");
    }

    // ─── Concurrent-refresh / thundering-herd protection ──────────────────────────

    [Fact]
    public async Task GetTokenAsync_ConcurrentCallers_ConvergeOnSingleTokenFetch()
    {
        // arrange — 50 callers race an empty cache. The 150ms delay ensures other callers actually
        // pile up on the semaphore; without it a fast machine could let the winner finish
        // before queueing starts, masking a regression in the dedup logic.
        var stub = new StubHttpMessageHandler
        {
            Responder = _ => TestProviderBuilder.TokenOk("jwt-shared", expiresIn: 3600),
            DelayPerRequest = TimeSpan.FromMilliseconds(150),
        };
        var provider = TestProviderBuilder.Build(stub);

        // act
        var tasks = Enumerable.Range(0, 50)
            .Select(_ => provider.GetTokenAsync("inventory-api", new[] { "inventory.read" }))
            .ToArray();
        var tokens = await Task.WhenAll(tasks);

        // assert
        tokens.Should().AllBe("jwt-shared");
        stub.CountRequestsContaining("/oauth/token").Should().Be(1,
            because: "the per-key semaphore is the only thing standing between us and a thundering herd at expiry.");
    }

    // ─── Keying ───────────────────────────────────────────────────────────────────

    [Fact]
    public async Task GetTokenAsync_DifferentAudienceOrScopeSets_CacheIndependently()
    {
        // arrange — three (audience, scopes) tuples = three cache keys. Cross-contamination would
        // either return the wrong token (security bug) or force unnecessary re-fetches.
        var counter = 0;
        var stub = new StubHttpMessageHandler
        {
            Responder = _ => TestProviderBuilder.TokenOk($"jwt-{Interlocked.Increment(ref counter)}", expiresIn: 3600),
        };
        var provider = TestProviderBuilder.Build(stub);

        // act
        var a = await provider.GetTokenAsync("inventory-api", new[] { "inventory.read" });
        var b = await provider.GetTokenAsync("inventory-api", new[] { "inventory.write" });   // different scopes
        var c = await provider.GetTokenAsync("orders-api", new[] { "inventory.read" });      // different audience

        // assert
        new[] { a, b, c }.Distinct().Should().HaveCount(3);
        stub.CountRequestsContaining("/oauth/token").Should().Be(3);
    }

    [Fact]
    public async Task GetTokenAsync_ScopeOrderInvariant_HitsSameCacheKey()
    {
        // arrange — cache key normalises scope order so callers don't have to remember it.
        var stub = new StubHttpMessageHandler();
        stub.ResponseQueue.Enqueue(TestProviderBuilder.TokenOk("jwt-ordered", expiresIn: 3600));
        var provider = TestProviderBuilder.Build(stub);

        // act
        var first = await provider.GetTokenAsync("aud", new[] { "read", "write" });
        var second = await provider.GetTokenAsync("aud", new[] { "write", "read" });

        // assert
        first.Should().Be("jwt-ordered");
        second.Should().Be("jwt-ordered");
        stub.CountRequestsContaining("/oauth/token").Should().Be(1);
    }

    // ─── Invalidate ───────────────────────────────────────────────────────────────

    [Fact]
    public async Task Invalidate_CausesNextCallToRefetch()
    {
        // arrange
        var stub = new StubHttpMessageHandler();
        stub.ResponseQueue.Enqueue(TestProviderBuilder.TokenOk("jwt-1", expiresIn: 3600));
        stub.ResponseQueue.Enqueue(TestProviderBuilder.TokenOk("jwt-2", expiresIn: 3600));
        var provider = TestProviderBuilder.Build(stub);

        // act
        var first = await provider.GetTokenAsync("aud", new[] { "read" });
        provider.Invalidate("aud", new[] { "read" });
        var second = await provider.GetTokenAsync("aud", new[] { "read" });

        // assert
        first.Should().Be("jwt-1");
        second.Should().Be("jwt-2");
        stub.CountRequestsContaining("/oauth/token").Should().Be(2);
    }

    // ─── 4xx config errors — no retry, surfaces OAuth code ───────────────────────

    [Fact]
    public async Task GetTokenAsync_4xxResponse_ThrowsServiceTokenExceptionWithOAuthCode_AndDoesNotRetry()
    {
        // arrange
        var stub = new StubHttpMessageHandler
        {
            Responder = _ => TestProviderBuilder.OAuthError("invalid_scope", "scope not permitted for this client"),
        };
        var options = new ServiceTokenClientOptions
        {
            Authority = TestProviderBuilder.DefaultAuthority,
            ClientId = "test-client",
            ClientSecret = "test-secret",
            TokenEndpointOverride = TestProviderBuilder.DefaultTokenEndpoint,
            MaxRetriesOnTransient = 5,  // would-retry-many if we hit the transient path; we shouldn't
        };
        var provider = TestProviderBuilder.Build(stub, options);

        // act + assert
        var act = async () => await provider.GetTokenAsync("aud", new[] { "forbidden.scope" });

        var ex = (await act.Should().ThrowAsync<ServiceTokenException>()).Subject.Single();
        ex.Error.Should().Be("invalid_scope");
        ex.ErrorDescription.Should().Be("scope not permitted for this client");
        stub.CountRequestsContaining("/oauth/token").Should().Be(1,
            because: "4xx means the request is wrong; retrying would just spam the auth service.");
    }

    // ─── 5xx transient — exponential backoff with bounded retries ────────────────

    [Fact]
    public async Task GetTokenAsync_5xxRepeatedly_RetriesUpToConfiguredMaxThenThrows()
    {
        // arrange
        var stub = new StubHttpMessageHandler
        {
            Responder = _ => TestProviderBuilder.Status(HttpStatusCode.ServiceUnavailable),
        };
        var options = new ServiceTokenClientOptions
        {
            Authority = TestProviderBuilder.DefaultAuthority,
            ClientId = "test-client",
            ClientSecret = "test-secret",
            TokenEndpointOverride = TestProviderBuilder.DefaultTokenEndpoint,
            MaxRetriesOnTransient = 2,
        };
        var provider = TestProviderBuilder.Build(stub, options);

        // act + assert
        var act = async () => await provider.GetTokenAsync("aud", new[] { "read" });

        var ex = (await act.Should().ThrowAsync<ServiceTokenException>()).Subject.Single();
        ex.Error.Should().Be("transient_failure");
        stub.CountRequestsContaining("/oauth/token").Should().Be(3,
            because: "MaxRetriesOnTransient=2 means 1 initial attempt + 2 retries = 3 total HTTP calls.");
    }

    [Fact]
    public async Task GetTokenAsync_5xxThenSuccess_RecoversWithoutThrowing()
    {
        // arrange
        var stub = new StubHttpMessageHandler();
        stub.ResponseQueue.Enqueue(TestProviderBuilder.Status(HttpStatusCode.InternalServerError));
        stub.ResponseQueue.Enqueue(TestProviderBuilder.TokenOk("jwt-recovered", expiresIn: 3600));
        var options = new ServiceTokenClientOptions
        {
            Authority = TestProviderBuilder.DefaultAuthority,
            ClientId = "test-client",
            ClientSecret = "test-secret",
            TokenEndpointOverride = TestProviderBuilder.DefaultTokenEndpoint,
            MaxRetriesOnTransient = 1,
        };
        var provider = TestProviderBuilder.Build(stub, options);

        // act
        var token = await provider.GetTokenAsync("aud", new[] { "read" });

        // assert
        token.Should().Be("jwt-recovered");
        stub.CountRequestsContaining("/oauth/token").Should().Be(2);
    }

    // ─── OIDC discovery ──────────────────────────────────────────────────────────

    [Fact]
    public async Task GetTokenAsync_WithoutTokenEndpointOverride_HitsDiscoveryOnceAndCachesIt()
    {
        // arrange — discovery doc is cached for process lifetime; a second token request (with a
        // different cache key to force a fetch) must NOT trigger a second discovery hit.
        var stub = new StubHttpMessageHandler
        {
            Responder = req =>
            {
                if (req.RequestUri!.AbsolutePath.EndsWith("/.well-known/openid-configuration", StringComparison.OrdinalIgnoreCase))
                {
                    return new HttpResponseMessage(HttpStatusCode.OK)
                    {
                        Content = JsonContent.Create(new
                        {
                            token_endpoint = "https://auth.example.test/oauth/token",
                        }),
                    };
                }
                return TestProviderBuilder.TokenOk($"jwt-{Guid.NewGuid():N}", expiresIn: 3600);
            },
        };
        var options = new ServiceTokenClientOptions
        {
            Authority = TestProviderBuilder.DefaultAuthority,
            ClientId = "test-client",
            ClientSecret = "test-secret",
            // TokenEndpointOverride deliberately NOT set — exercising the discovery path.
            MaxRetriesOnTransient = 0,
        };
        var provider = TestProviderBuilder.Build(stub, options);

        // act — two different cache keys force two token requests.
        await provider.GetTokenAsync("aud-1", new[] { "read" });
        await provider.GetTokenAsync("aud-2", new[] { "read" });

        // assert
        stub.CountRequestsContaining("/.well-known/openid-configuration").Should().Be(1,
            because: "the discovery doc URL is stable across a deploy; refetching it on every token request would be silly.");
        stub.CountRequestsContaining("/oauth/token").Should().Be(2);
    }

    [Fact]
    public async Task GetTokenAsync_WithTokenEndpointOverride_SkipsDiscovery()
    {
        // arrange
        var stub = new StubHttpMessageHandler
        {
            Responder = _ => TestProviderBuilder.TokenOk("jwt-x", expiresIn: 3600),
        };
        var provider = TestProviderBuilder.Build(stub);  // builder sets override by default

        // act
        await provider.GetTokenAsync("aud", new[] { "read" });

        // assert
        stub.CountRequestsContaining("/.well-known").Should().Be(0,
            because: "TokenEndpointOverride is the explicit operator opt-out from discovery.");
        stub.CountRequestsContaining("/oauth/token").Should().Be(1);
    }
}
