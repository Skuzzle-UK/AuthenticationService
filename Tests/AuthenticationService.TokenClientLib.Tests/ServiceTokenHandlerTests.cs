using AwesomeAssertions;
using NSubstitute;
using NSubstitute.ExceptionExtensions;
using System.Net;
using System.Net.Http.Headers;

namespace AuthenticationService.TokenClientLib.Tests;

/// <summary>
/// Covers the ServiceTokenHandler contract: stamp Bearer on every outgoing request;
/// retry exactly once on RFC 6750 invalid_token hint; pass through plain 401s
/// unchanged; bubble up provider failures before any outgoing call.
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

        // assert — RFC 6750 §2.1: no quotes, no extra spaces.
        response.StatusCode.Should().Be(HttpStatusCode.OK);
        inner.LastRequest!.Headers.Authorization!.Scheme.Should().Be("Bearer");
        inner.LastRequest.Headers.Authorization.Parameter.Should().Be("jwt-stamped");
        inner.RequestCount.Should().Be(1, because: "happy path is single outgoing call.");
    }

    [Fact]
    public async Task SendAsync_Downstream401WithInvalidToken_InvalidatesAndRetriesOnceWithFreshToken()
    {
        // arrange
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

        // assert — three things must all be true: Invalidate called, retry happened, and the
        // retry used the fresh token (not the stale one).
        response.StatusCode.Should().Be(HttpStatusCode.OK);
        provider.Received(1).Invalidate("aud", Arg.Any<IReadOnlyList<string>>());
        inner.RequestCount.Should().Be(2);
        inner.RequestsByIndex[0].Headers.Authorization!.Parameter.Should().Be("jwt-stale");
        inner.RequestsByIndex[1].Headers.Authorization!.Parameter.Should().Be("jwt-fresh");
    }

    [Fact]
    public async Task SendAsync_401WithoutInvalidTokenHint_PassesThroughWithoutRetrying()
    {
        // arrange — plain 401 (no invalid_token hint) usually means authorisation-policy denial;
        // refreshing the token won't fix that. Pass straight to the consumer.
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

        // assert
        response.StatusCode.Should().Be(HttpStatusCode.Unauthorized);
        provider.DidNotReceive().Invalidate(Arg.Any<string>(), Arg.Any<IReadOnlyList<string>>());
        inner.RequestCount.Should().Be(1);
    }

    [Fact]
    public async Task SendAsync_TwoConsecutiveInvalidTokenResponses_BubblesSecond401Up()
    {
        // arrange — two invalid_token responses in a row; credentials don't work, so give up rather
        // than spam the auth service.
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

        // assert
        response.StatusCode.Should().Be(HttpStatusCode.Unauthorized);
        inner.RequestCount.Should().Be(2,
            because: "we retry exactly once; a third call would either spam the downstream or imply infinite recursion.");
        provider.Received(1).Invalidate("aud", Arg.Any<IReadOnlyList<string>>());
    }

    [Fact]
    public async Task SendAsync_ProviderThrows_BubblesUpAndDoesNotSendRequest()
    {
        // arrange — a provider failure must never result in an unauthenticated outgoing call;
        // downstream would 401 for a completely different (and confusing) reason.
        var provider = Substitute.For<IServiceTokenProvider>();
        provider
            .GetTokenAsync(Arg.Any<string>(), Arg.Any<IReadOnlyList<string>>(), Arg.Any<CancellationToken>())
            .Throws(new ServiceTokenException("invalid_client", "secret rotated and we missed it"));

        var inner = new RecordingInnerHandler(_ =>
            throw new InvalidOperationException("handler should not have sent a request"));
        var handler = new ServiceTokenHandler(provider, "aud", new[] { "read" }) { InnerHandler = inner };
        using var invoker = new HttpMessageInvoker(handler, disposeHandler: false);

        // act + assert
        using var request = new HttpRequestMessage(HttpMethod.Get, "https://downstream/api");
        var act = async () => await invoker.SendAsync(request, CancellationToken.None);

        var thrown = (await act.Should().ThrowAsync<ServiceTokenException>()).Subject.Single();
        thrown.Error.Should().Be("invalid_client");
        inner.RequestCount.Should().Be(0,
            because: "without a valid token we never want to expose downstream traffic to silent unauthenticated calls.");
    }

    // ─── Helpers ──────────────────────────────────────────────────────────────────

    /// <summary>
    /// Builds the 401 + WWW-Authenticate shape from RFC 6750 §3.
    /// </summary>
    private static HttpResponseMessage UnauthorizedWithInvalidTokenHint()
    {
        var response = new HttpResponseMessage(HttpStatusCode.Unauthorized);
        response.Headers.WwwAuthenticate.Add(new AuthenticationHeaderValue("Bearer", "error=\"invalid_token\""));
        return response;
    }

    /// <summary>
    /// Inner handler that records each request with its Authorization header snapshotted,
    /// so tests can distinguish "retried with stale" from "retried with fresh".
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
            // Snapshot Authorization — DelegatingHandler may mutate headers between attempts,
            // and the stale-vs-fresh assertion needs each attempt's value captured at send time.
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
