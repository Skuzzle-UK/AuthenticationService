namespace AuthenticationService.TokenClientLib.Tests.Helpers;

/// <summary>
/// Test double for HttpMessageHandler. Two response modes: <see cref="Responder"/> (per-
/// request delegate, wins if both are set) and <see cref="ResponseQueue"/> (pre-canned
/// FIFO). Records every request for assertions. <see cref="DelayPerRequest"/> slows
/// responses to exercise concurrent-refresh deduplication.
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

    /// <summary>
    /// Convenience: number of recorded requests whose URL contains <paramref name="urlSubstring"/>.
    /// </summary>
    public int CountRequestsContaining(string urlSubstring)
    {
        lock (_gate)
        {
            return _requests.Count(r =>
                r.RequestUri!.AbsoluteUri.Contains(urlSubstring, StringComparison.OrdinalIgnoreCase));
        }
    }
}
