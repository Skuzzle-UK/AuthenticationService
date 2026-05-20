using AwesomeAssertions;
using NSubstitute;
using NSubstitute.ExceptionExtensions;
using System.Net;
using System.Net.Http.Headers;

namespace AuthenticationService.TokenClientLib.Tests;

/// <summary>
/// <para>The handler is the seam that turns "consumer's HttpClient call" into "outgoing call
/// with a valid Bearer header." Its contract is small but every line of it matters:</para>
/// <list type="bullet">
///   <item><description>Every outgoing request gets <c>Authorization: Bearer &lt;token&gt;</c> stamped — a regression that skips this means downstream calls 401 with no clear cause.</description></item>
///   <item><description>A downstream 401 with <c>WWW-Authenticate: Bearer error="invalid_token"</c> (RFC 6750 §3) triggers exactly one cache-invalidate + retry. Any other 401 reason (auth-policy denial, missing role) passes through unchanged because re-fetching the token would not help.</description></item>
///   <item><description>Two consecutive token-shaped 401s bubble up — credentials genuinely don't work, calling the auth service in a hot loop won't fix it.</description></item>
///   <item><description>Provider failures (e.g. <c>ServiceTokenException</c> on bad config) bubble up <em>before</em> any outgoing call is made — we never send a request without a token.</description></item>
/// </list>
///
/// <para>Tests drive the handler via <see cref="HttpMessageInvoker"/> with a substituted
/// <see cref="IServiceTokenProvider"/> and a <see cref="RecordingInnerHandler"/> at the end
/// of the pipeline — no live HTTP needed.</para>
/// </summary>
public class ServiceTokenHandlerTests
{
    [Fact]
    public async Task SendAsync_StampsBearerTokenAndForwardsRequest()
    {
        // arrange
        var provider = Substitute.For<IServiceTokenProvider>();
        provider
            .GetTokenAsync("inventory-api", Arg.Any<IReadOnlyList<string>>(), Arg.Any<CancellationToken>())
            .Returns("jwt-stamped");

        var inner = new RecordingInnerHandler(_ => new HttpResponseMessage(HttpStatusCode.OK));
        var handler = new ServiceTokenHandler(provider, "inventory-api", new[] { "inventory.read" }) { InnerHandler = inner };
        using var invoker = new HttpMessageInvoker(handler, disposeHandler: false);

        // act
        using var request = new HttpRequestMessage(HttpMethod.Get, "https://inventory.svc/items/1");
        using var response = await invoker.SendAsync(request, CancellationToken.None);

        // assert — header shape exactly as RFC 6750 §2.1 specifies (no quotes, no extra spaces).
        response.StatusCode.Should().Be(HttpStatusCode.OK);
        inner.LastRequest!.Headers.Authorization!.Scheme.Should().Be("Bearer");
        inner.LastRequest.Headers.Authorization.Parameter.Should().Be("jwt-stamped");
        inner.RequestCount.Should().Be(1, because: "happy path is single outgoing call.");
    }

    [Fact]
    public async Task SendAsync_Downstream401WithInvalidToken_InvalidatesAndRetriesOnceWithFreshToken()
    {
        // arrange — first downstream response is 401 + RFC 6750 invalid_token hint. The
        // handler must invalidate the cached token and retry once. Provider returns a new
        // token on the second GetTokenAsync call.
        var provider = Substitute.For<IServiceTokenProvider>();
        provider
            .GetTokenAsync("aud", Arg.Any<IReadOnlyList<string>>(), Arg.Any<CancellationToken>())
            .Returns("jwt-stale", "jwt-fresh");

        var responseScript = new Queue<HttpResponseMessage>();
        responseScript.Enqueue(UnauthorizedWithInvalidTokenHint());
        responseScript.Enqueue(new HttpResponseMessage(HttpStatusCode.OK));
        var inner = new RecordingInnerHandler(_ => responseScript.Dequeue());
        var handler = new ServiceTokenHandler(provider, "aud", new[] { "read" }) { InnerHandler = inner };
        using var invoker = new HttpMessageInvoker(handler, disposeHandler: false);

        // act
        using var request = new HttpRequestMessage(HttpMethod.Get, "https://downstream/api");
        using var response = await invoker.SendAsync(request, CancellationToken.None);

        // assert — the retry produced a 200; the cache was invalidated; the second outgoing
        // call carried the fresh token, not the stale one. Each part of this matters:
        //   - missing Invalidate → provider would just hand back the same dead token forever
        //   - missing retry      → consumer sees a 401 even though the cache is bust
        //   - wrong token order  → we retried with the same stale token (silent bug)
        response.StatusCode.Should().Be(HttpStatusCode.OK);
        provider.Received(1).Invalidate("aud", Arg.Any<IReadOnlyList<string>>());
        inner.RequestCount.Should().Be(2);
        inner.RequestsByIndex[0].Headers.Authorization!.Parameter.Should().Be("jwt-stale");
        inner.RequestsByIndex[1].Headers.Authorization!.Parameter.Should().Be("jwt-fresh");
    }

    [Fact]
    public async Task SendAsync_401WithoutInvalidTokenHint_PassesThroughWithoutRetrying()
    {
        // arrange — a plain 401 (no WWW-Authenticate, or one without invalid_token) usually
        // means an authorisation-policy denial: "your token is valid but you don't have that
        // permission." Refreshing the token would NOT fix that, and re-asking the auth
        // service for the same scope set would waste calls. So we pass the 401 straight to
        // the consumer.
        var provider = Substitute.For<IServiceTokenProvider>();
        provider
            .GetTokenAsync("aud", Arg.Any<IReadOnlyList<string>>(), Arg.Any<CancellationToken>())
            .Returns("jwt-valid");

        var inner = new RecordingInnerHandler(_ => new HttpResponseMessage(HttpStatusCode.Unauthorized));
        var handler = new ServiceTokenHandler(provider, "aud", new[] { "read" }) { InnerHandler = inner };
        using var invoker = new HttpMessageInvoker(handler, disposeHandler: false);

        // act
        using var request = new HttpRequestMessage(HttpMethod.Get, "https://downstream/api");
        using var response = await invoker.SendAsync(request, CancellationToken.None);

        // assert — single outgoing call, no Invalidate, 401 returned unchanged.
        response.StatusCode.Should().Be(HttpStatusCode.Unauthorized);
        provider.DidNotReceive().Invalidate(Arg.Any<string>(), Arg.Any<IReadOnlyList<string>>());
        inner.RequestCount.Should().Be(1);
    }

    [Fact]
    public async Task SendAsync_TwoConsecutiveInvalidTokenResponses_BubblesSecond401Up()
    {
        // arrange — both attempts return invalid_token. After the second 401 the handler
        // must give up: the credentials themselves don't work and another round-trip would
        // just waste time. The second 401 is what the consumer sees — they need to know
        // the retry happened and still failed.
        var provider = Substitute.For<IServiceTokenProvider>();
        provider
            .GetTokenAsync("aud", Arg.Any<IReadOnlyList<string>>(), Arg.Any<CancellationToken>())
            .Returns("jwt-1", "jwt-2");

        var inner = new RecordingInnerHandler(_ => UnauthorizedWithInvalidTokenHint());
        var handler = new ServiceTokenHandler(provider, "aud", new[] { "read" }) { InnerHandler = inner };
        using var invoker = new HttpMessageInvoker(handler, disposeHandler: false);

        // act
        using var request = new HttpRequestMessage(HttpMethod.Get, "https://downstream/api");
        using var response = await invoker.SendAsync(request, CancellationToken.None);

        // assert — exactly two outgoing calls, Invalidate called once after the first 401,
        // final response is the second 401.
        response.StatusCode.Should().Be(HttpStatusCode.Unauthorized);
        inner.RequestCount.Should().Be(2,
            because: "we retry exactly once; a third call would either spam the downstream or imply infinite recursion.");
        provider.Received(1).Invalidate("aud", Arg.Any<IReadOnlyList<string>>());
    }

    [Fact]
    public async Task SendAsync_ProviderThrows_BubblesUpAndDoesNotSendRequest()
    {
        // arrange — if GetTokenAsync throws (bad config, unauth'd client) the handler must
        // surface the exception without making a tokenless outgoing call. Otherwise we'd
        // leak unauthenticated traffic to the downstream service, which would then 401 it
        // for an entirely different (and confusing) reason.
        var provider = Substitute.For<IServiceTokenProvider>();
        provider
            .GetTokenAsync(Arg.Any<string>(), Arg.Any<IReadOnlyList<string>>(), Arg.Any<CancellationToken>())
            .Throws(new ServiceTokenException("invalid_client", "secret rotated and we missed it"));

        var inner = new RecordingInnerHandler(_ =>
            throw new InvalidOperationException("handler should not have sent a request"));
        var handler = new ServiceTokenHandler(provider, "aud", new[] { "read" }) { InnerHandler = inner };
        using var invoker = new HttpMessageInvoker(handler, disposeHandler: false);

        // act
        using var request = new HttpRequestMessage(HttpMethod.Get, "https://downstream/api");
        var act = async () => await invoker.SendAsync(request, CancellationToken.None);

        // assert — the typed exception bubbles up unchanged; no outgoing call made.
        var thrown = (await act.Should().ThrowAsync<ServiceTokenException>()).Subject.Single();
        thrown.Error.Should().Be("invalid_client");
        inner.RequestCount.Should().Be(0,
            because: "without a valid token we never want to expose downstream traffic to silent unauthenticated calls.");
    }

    // ─── Helpers ──────────────────────────────────────────────────────────────────

    /// <summary>
    /// Builds the exact 401 + WWW-Authenticate shape the handler is documented to react to,
    /// per RFC 6750 §3. The error param can be in any case; we put it in lower case here.
    /// </summary>
    private static HttpResponseMessage UnauthorizedWithInvalidTokenHint()
    {
        var response = new HttpResponseMessage(HttpStatusCode.Unauthorized);
        response.Headers.WwwAuthenticate.Add(new AuthenticationHeaderValue("Bearer", "error=\"invalid_token\""));
        return response;
    }

    /// <summary>
    /// Inner handler that records each request it sees + delegates response-building to a
    /// caller-supplied lambda. Stores requests by index so tests can assert on the exact
    /// header value the handler stamped on each attempt (otherwise we couldn't distinguish
    /// "retried with the stale token" from "retried with the fresh token" — the difference
    /// matters).
    /// </summary>
    private sealed class RecordingInnerHandler : HttpMessageHandler
    {
        private readonly Func<HttpRequestMessage, HttpResponseMessage> _responder;
        private readonly List<HttpRequestMessage> _requests = new();
        public RecordingInnerHandler(Func<HttpRequestMessage, HttpResponseMessage> responder)
        {
            _responder = responder;
        }

        public int RequestCount => _requests.Count;
        public HttpRequestMessage? LastRequest => _requests.LastOrDefault();
        public IReadOnlyList<HttpRequestMessage> RequestsByIndex => _requests;

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
        {
            // Clone what we care about — DelegatingHandler may mutate headers between attempts.
            // We snapshot Authorization specifically because the test asserts on stale-vs-fresh.
            var snapshot = new HttpRequestMessage(request.Method, request.RequestUri);
            if (request.Headers.Authorization is not null)
            {
                snapshot.Headers.Authorization = new AuthenticationHeaderValue(
                    request.Headers.Authorization.Scheme,
                    request.Headers.Authorization.Parameter);
            }
            _requests.Add(snapshot);

            return Task.FromResult(_responder(request));
        }
    }
}
