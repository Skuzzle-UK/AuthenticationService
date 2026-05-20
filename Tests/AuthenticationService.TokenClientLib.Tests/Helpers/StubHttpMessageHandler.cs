namespace AuthenticationService.TokenClientLib.Tests.Helpers;

/// <summary>
/// Tiny test double for <see cref="HttpMessageHandler"/>. Lets tests drive the
/// provider's HTTP traffic deterministically without spinning up a real auth server.
///
/// <para>Two response modes — pick whichever shape fits the test:
/// <list type="bullet">
///   <item><description><see cref="Responder"/> — a delegate that builds a response per
///   request. Use when the response depends on the URL / method (e.g. "discovery → doc;
///   token endpoint → JWT").</description></item>
///   <item><description><see cref="ResponseQueue"/> — pre-canned responses popped in
///   order. Use for "first call returns 500, second returns 200" style scripts.</description></item>
/// </list>
/// If both are set, <see cref="Responder"/> wins.</para>
///
/// <para>Records every request URL for assertions. <see cref="DelayPerRequest"/> slows
/// responses to test concurrent-refresh deduplication — set this above zero to make
/// the first refresh take long enough for queued callers to pile up on the semaphore.</para>
/// </summary>
internal sealed class StubHttpMessageHandler : HttpMessageHandler
{
    private readonly object _gate = new();
    private readonly List<HttpRequestMessage> _requests = new();

    public IReadOnlyList<HttpRequestMessage> Requests
    {
        get { lock (_gate) { return _requests.ToList(); } }
    }

    public Queue<HttpResponseMessage> ResponseQueue { get; } = new();
    public Func<HttpRequestMessage, HttpResponseMessage>? Responder { get; set; }
    public TimeSpan DelayPerRequest { get; set; } = TimeSpan.Zero;

    protected override async Task<HttpResponseMessage> SendAsync(
        HttpRequestMessage request, CancellationToken ct)
    {
        lock (_gate) { _requests.Add(request); }

        if (DelayPerRequest > TimeSpan.Zero)
        {
            await Task.Delay(DelayPerRequest, ct);
        }

        if (Responder is not null)
        {
            return Responder(request);
        }
        lock (_gate)
        {
            if (ResponseQueue.TryDequeue(out var queued))
            {
                return queued;
            }
        }
        throw new InvalidOperationException(
            $"StubHttpMessageHandler had no response configured for {request.Method} {request.RequestUri}.");
    }

    /// <summary>Convenience: number of recorded requests whose URL contains <paramref name="urlSubstring"/>.</summary>
    public int CountRequestsContaining(string urlSubstring)
    {
        lock (_gate)
        {
            return _requests.Count(r =>
                r.RequestUri!.AbsoluteUri.Contains(urlSubstring, StringComparison.OrdinalIgnoreCase));
        }
    }
}
