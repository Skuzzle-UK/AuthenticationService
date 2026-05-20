using AuthenticationService.TokenClientLib.Tests.Helpers;
using AwesomeAssertions;
using System.Net;
using System.Net.Http.Json;

namespace AuthenticationService.TokenClientLib.Tests;

/// <summary>
/// <para>These tests pin the behavioural contract documented in
/// <c>docs/service-token-client-plan.md</c> §"Confirmed design decisions". The cache /
/// refresh / discovery / retry semantics are what make this lib safe to drop into a
/// production microservice — a regression in any of them shows up as silent token
/// thrash, duplicate <c>/oauth/token</c> hits at expiry, or surprising failures in the
/// face of transient backend wobble.</para>
///
/// <para>HTTP is driven by <see cref="StubHttpMessageHandler"/> — no live server,
/// deterministic timing where possible, real <see cref="Task.Delay"/>-driven where
/// the proactive-refresh path inherently needs real wall-clock time.</para>
/// </summary>
public class ServiceTokenProviderTests
{
    // ─── Happy path ───────────────────────────────────────────────────────────────

    [Fact]
    public async Task GetTokenAsync_FirstCall_FetchesViaHttpAndReturnsAccessToken()
    {
        // arrange — TokenEndpointOverride skips discovery so the test asserts only one HTTP hit.
        var stub = new StubHttpMessageHandler
        {
            Responder = _ => TestProviderBuilder.TokenOk("jwt-aaa"),
        };
        var provider = TestProviderBuilder.Build(stub);

        // act
        var token = await provider.GetTokenAsync("inventory-api", new[] { "inventory.read" });

        // assert — the access_token field of the OAuth response is what we hand back to callers.
        token.Should().Be("jwt-aaa");
        stub.CountRequestsContaining("/oauth/token").Should().Be(1);
    }

    [Fact]
    public async Task GetTokenAsync_TokenRequest_UsesBasicAuthAndClientCredentialsBody()
    {
        // arrange — capture the request wire format from INSIDE the responder. The provider
        // wraps its request in `using` so it's disposed by the time the test resumes; reading
        // Content afterwards would hit ObjectDisposedException. The responder runs while the
        // request is still alive.
        //
        // The OAuth spec says credentials in Basic header + grant_type=client_credentials in
        // body (§2.3.1). A regression here would silently break compatibility with the auth
        // service's /oauth/token endpoint and a real consumer would only find out in production.
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

        // assert — the request used Basic auth + the right body params in the right shape.
        capturedMethod.Should().Be(HttpMethod.Post);
        capturedAuthScheme.Should().Be("Basic");
        capturedBody.Should().Contain("grant_type=client_credentials");
        capturedBody.Should().Contain("audience=inventory-api");
        // scopes URL-encode the space to '+' in form-encoding.
        capturedBody.Should().Contain("scope=inventory.read+inventory.write");
    }

    // ─── Cache ────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task GetTokenAsync_SecondCallWithinLifetime_ReturnsCachedToken()
    {
        // arrange — the first call mints; the second is well within the (default-0.8) refresh
        // threshold on a 1-hour token, so it must hit cache and skip the network entirely.
        var stub = new StubHttpMessageHandler();
        stub.ResponseQueue.Enqueue(TestProviderBuilder.TokenOk("jwt-once", expiresIn: 3600));
        var provider = TestProviderBuilder.Build(stub);

        // act
        var first = await provider.GetTokenAsync("inventory-api", new[] { "inventory.read" });
        var second = await provider.GetTokenAsync("inventory-api", new[] { "inventory.read" });

        // assert — identical value AND no second network call.
        second.Should().Be(first);
        stub.CountRequestsContaining("/oauth/token").Should().Be(1);
    }

    [Fact]
    public async Task GetTokenAsync_PastExpiry_BlocksOnRefreshAndReturnsNewToken()
    {
        // arrange — expires_in = -1 forces the cached token's IsValid() to be false on the
        // very next call, sending the second call through the slow refresh path.
        var stub = new StubHttpMessageHandler();
        stub.ResponseQueue.Enqueue(TestProviderBuilder.TokenOk("jwt-old", expiresIn: -1));
        stub.ResponseQueue.Enqueue(TestProviderBuilder.TokenOk("jwt-new", expiresIn: 3600));
        var provider = TestProviderBuilder.Build(stub);

        // act
        var first = await provider.GetTokenAsync("aud", new[] { "read" });
        var second = await provider.GetTokenAsync("aud", new[] { "read" });

        // assert — the refresh actually happened. Two distinct tokens, two HTTP hits.
        first.Should().Be("jwt-old");
        second.Should().Be("jwt-new");
        stub.CountRequestsContaining("/oauth/token").Should().Be(2);
    }

    [Fact]
    public async Task GetTokenAsync_PastProactiveThreshold_ReturnsCurrentAndRefreshesInBackground()
    {
        // arrange — RefreshAtFractionOfLifetime = 0.0 means "refresh threshold == issuedAt", so the
        // second call sees the cached token as valid AND past the proactive threshold. The provider
        // must return the cached token immediately AND fire a background refresh — exactly the
        // behaviour that smooths over the expiry boundary without making the user-facing call wait.
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

        // assert — both calls return the still-valid cached token; the second one also
        // schedules a fire-and-forget refresh.
        first.Should().Be("jwt-current");
        second.Should().Be("jwt-current",
            because: "the user-facing call should never block on the background refresh — that's the whole point of the proactive window.");

        // Wait for the background refresh to land. Without this, a fast machine might
        // race past the assert; without a timeout, a stuck machine would hang the suite.
        await TestProviderBuilder.WaitUntilAsync(() => stub.CountRequestsContaining("/oauth/token") == 2);

        // And the cached token has been swapped — a third call returns the new value with no extra HTTP traffic.
        var third = await provider.GetTokenAsync("aud", new[] { "read" });
        third.Should().Be("jwt-refreshed");
        stub.CountRequestsContaining("/oauth/token").Should().Be(2,
            because: "the third call hits the freshly-refreshed cache; nothing else should fire.");
    }

    // ─── Concurrent-refresh / thundering-herd protection ──────────────────────────

    [Fact]
    public async Task GetTokenAsync_ConcurrentCallers_ConvergeOnSingleTokenFetch()
    {
        // arrange — 50 callers race into an empty cache. Without the per-key SemaphoreSlim
        // every one of them would hit /oauth/token; with it, exactly one wins and the other 49
        // re-check the cache after acquiring the lock and find the freshly-minted token.
        var stub = new StubHttpMessageHandler
        {
            Responder = _ => TestProviderBuilder.TokenOk("jwt-shared", expiresIn: 3600),
            // Slow the first fetch enough for the other callers to genuinely pile up on the
            // semaphore — without this, on a very fast machine the winner could finish before
            // the other tasks even reach the wait, masking a regression in the dedup logic.
            DelayPerRequest = TimeSpan.FromMilliseconds(150),
        };
        var provider = TestProviderBuilder.Build(stub);

        // act — fire 50 tasks at the same audience/scopes.
        var tasks = Enumerable.Range(0, 50)
            .Select(_ => provider.GetTokenAsync("inventory-api", new[] { "inventory.read" }))
            .ToArray();
        var tokens = await Task.WhenAll(tasks);

        // assert — every caller got the same token AND only one HTTP hit happened.
        tokens.Should().AllBe("jwt-shared");
        stub.CountRequestsContaining("/oauth/token").Should().Be(1,
            because: "the per-key semaphore is the only thing standing between us and a thundering herd at expiry.");
    }

    // ─── Keying ───────────────────────────────────────────────────────────────────

    [Fact]
    public async Task GetTokenAsync_DifferentAudienceOrScopeSets_CacheIndependently()
    {
        // arrange — three different (audience, scopes) tuples are three different cache keys.
        // Mixing them would either return the wrong token (security bug — wrong audience claim
        // on the outgoing call) or cause unnecessary re-fetches.
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

        // assert — three distinct fetches AND three distinct tokens.
        new[] { a, b, c }.Distinct().Should().HaveCount(3);
        stub.CountRequestsContaining("/oauth/token").Should().Be(3);
    }

    [Fact]
    public async Task GetTokenAsync_ScopeOrderInvariant_HitsSameCacheKey()
    {
        // arrange — ["read", "write"] and ["write", "read"] mean the same thing semantically.
        // The cache key normalises by sorting so callers don't have to remember an order.
        var stub = new StubHttpMessageHandler();
        stub.ResponseQueue.Enqueue(TestProviderBuilder.TokenOk("jwt-ordered", expiresIn: 3600));
        var provider = TestProviderBuilder.Build(stub);

        // act
        var first = await provider.GetTokenAsync("aud", new[] { "read", "write" });
        var second = await provider.GetTokenAsync("aud", new[] { "write", "read" });

        // assert — second call hits the same cache slot, no second HTTP hit.
        first.Should().Be("jwt-ordered");
        second.Should().Be("jwt-ordered");
        stub.CountRequestsContaining("/oauth/token").Should().Be(1);
    }

    // ─── Invalidate ───────────────────────────────────────────────────────────────

    [Fact]
    public async Task Invalidate_CausesNextCallToRefetch()
    {
        // arrange — Invalidate is the hook ServiceTokenHandler uses on a downstream 401 with
        // an invalid_token hint. If it doesn't actually drop the cache, the retry-with-fresh-token
        // path doesn't work and consumers see persistent 401s after the auth service rotates keys.
        var stub = new StubHttpMessageHandler();
        stub.ResponseQueue.Enqueue(TestProviderBuilder.TokenOk("jwt-1", expiresIn: 3600));
        stub.ResponseQueue.Enqueue(TestProviderBuilder.TokenOk("jwt-2", expiresIn: 3600));
        var provider = TestProviderBuilder.Build(stub);

        // act
        var first = await provider.GetTokenAsync("aud", new[] { "read" });
        provider.Invalidate("aud", new[] { "read" });
        var second = await provider.GetTokenAsync("aud", new[] { "read" });

        // assert — the second call refetches because Invalidate dropped the cached entry.
        first.Should().Be("jwt-1");
        second.Should().Be("jwt-2");
        stub.CountRequestsContaining("/oauth/token").Should().Be(2);
    }

    // ─── 4xx config errors — no retry, surfaces OAuth code ───────────────────────

    [Fact]
    public async Task GetTokenAsync_4xxResponse_ThrowsServiceTokenExceptionWithOAuthCode_AndDoesNotRetry()
    {
        // arrange — 400 with a {error, error_description} body. The exception must carry the
        // OAuth code so consumers can branch on invalid_client / invalid_scope / etc. AND we
        // must not retry — 4xx is a config / credential failure that retrying can't fix
        // (and would just hammer the auth service for nothing).
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

        // act
        var act = async () => await provider.GetTokenAsync("aud", new[] { "forbidden.scope" });

        // assert — typed exception, OAuth code preserved, exactly one HTTP hit (no retry).
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
        // arrange — keep returning 503. With MaxRetriesOnTransient=2 we expect 3 total
        // attempts (initial + 2 retries) before the provider gives up with transient_failure.
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

        // act — measure roughly so the backoff doesn't hang the suite if something is wrong.
        var act = async () => await provider.GetTokenAsync("aud", new[] { "read" });

        // assert — typed exception with transient_failure code; the count proves we honoured
        // the retry budget exactly (no over-retry, no under-retry).
        var ex = (await act.Should().ThrowAsync<ServiceTokenException>()).Subject.Single();
        ex.Error.Should().Be("transient_failure");
        stub.CountRequestsContaining("/oauth/token").Should().Be(3,
            because: "MaxRetriesOnTransient=2 means 1 initial attempt + 2 retries = 3 total HTTP calls.");
    }

    [Fact]
    public async Task GetTokenAsync_5xxThenSuccess_RecoversWithoutThrowing()
    {
        // arrange — a single transient blip is exactly the situation retries exist for.
        // First attempt 500, second attempt 200 — provider should hand back the token cleanly.
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

        // assert — the retry actually delivered the recovered token.
        token.Should().Be("jwt-recovered");
        stub.CountRequestsContaining("/oauth/token").Should().Be(2);
    }

    // ─── OIDC discovery ──────────────────────────────────────────────────────────

    [Fact]
    public async Task GetTokenAsync_WithoutTokenEndpointOverride_HitsDiscoveryOnceAndCachesIt()
    {
        // arrange — no override, so the provider must discover token_endpoint via
        // /.well-known/openid-configuration. The doc is cached for the process lifetime
        // so a second token request (with a different cache key, to force a refetch)
        // must NOT trigger a second discovery hit.
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
            // TokenEndpointOverride deliberately NOT set — we want the discovery path.
            MaxRetriesOnTransient = 0,
        };
        var provider = TestProviderBuilder.Build(stub, options);

        // act — two calls with different cache keys to force two token requests.
        await provider.GetTokenAsync("aud-1", new[] { "read" });
        await provider.GetTokenAsync("aud-2", new[] { "read" });

        // assert — exactly one discovery hit AND two token hits.
        stub.CountRequestsContaining("/.well-known/openid-configuration").Should().Be(1,
            because: "the discovery doc URL is stable across a deploy; refetching it on every token request would be silly.");
        stub.CountRequestsContaining("/oauth/token").Should().Be(2);
    }

    [Fact]
    public async Task GetTokenAsync_WithTokenEndpointOverride_SkipsDiscovery()
    {
        // arrange — TokenEndpointOverride lets tests + air-gapped environments bypass discovery.
        // If the override is honoured we never see a /.well-known/* request.
        var stub = new StubHttpMessageHandler
        {
            Responder = _ => TestProviderBuilder.TokenOk("jwt-x", expiresIn: 3600),
        };
        var provider = TestProviderBuilder.Build(stub);  // override is set by default in the builder

        // act
        await provider.GetTokenAsync("aud", new[] { "read" });

        // assert — discovery never touched, exactly one token request.
        stub.CountRequestsContaining("/.well-known").Should().Be(0,
            because: "TokenEndpointOverride is the explicit operator opt-out from discovery.");
        stub.CountRequestsContaining("/oauth/token").Should().Be(1);
    }
}
