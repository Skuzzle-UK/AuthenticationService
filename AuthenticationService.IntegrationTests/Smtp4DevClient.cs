using System.Net.Http.Json;

namespace AuthenticationService.IntegrationTests;

/// <summary>
/// Thin client for smtp4dev's HTTP API. Used by integration tests to assert sent emails
/// and pull links out of message bodies.
/// </summary>
public sealed class Smtp4DevClient
{
    private readonly HttpClient _client;

    public Smtp4DevClient(HttpClient client)
    {
        _client = client;
    }

    /// <summary>
    /// Lists inbox messages, most-recent-first.
    /// </summary>
    public async Task<IReadOnlyList<Smtp4DevMessage>> ListMessagesAsync(CancellationToken ct = default)
    {
        var page = await _client.GetFromJsonAsync<MessagesPage>(
            "/api/Messages?pageSize=100&sortColumn=receivedDate&sortIsDescending=true",
            ct);
        return page?.Results ?? [];
    }

    /// <summary>
    /// Returns the HTML body of the message.
    /// </summary>
    public async Task<string> GetMessageHtmlAsync(Guid messageId, CancellationToken ct = default)
    {
        var response = await _client.GetAsync($"/api/Messages/{messageId}/html", ct);
        response.EnsureSuccessStatusCode();
        return await response.Content.ReadAsStringAsync(ct);
    }

    /// <summary>
    /// Wipes every message from the inbox.
    /// </summary>
    public async Task ClearAsync(CancellationToken ct = default)
    {
        var response = await _client.DeleteAsync("/api/Messages/*", ct);
        response.EnsureSuccessStatusCode();
    }

    /// <summary>
    /// Polls until a message addressed to <paramref name="toEmail"/> arrives, or
    /// <paramref name="timeout"/> passes. Returns null on timeout.
    /// </summary>
    public async Task<Smtp4DevMessage?> WaitForMessageAsync(
        string toEmail,
        TimeSpan timeout,
        CancellationToken ct = default)
    {
        var deadline = DateTime.UtcNow + timeout;
        while (DateTime.UtcNow < deadline)
        {
            var messages = await ListMessagesAsync(ct);
            var match = messages.FirstOrDefault(m =>
                m.To?.Any(t => t.Equals(toEmail, StringComparison.OrdinalIgnoreCase)) == true);
            if (match is not null)
            {
                return match;
            }
            await Task.Delay(200, ct);
        }
        return null;
    }

    private sealed record MessagesPage(IReadOnlyList<Smtp4DevMessage> Results, int RowCount);
}

/// <summary>
/// Subset of smtp4dev's message shape used by integration tests.
/// </summary>
public sealed record Smtp4DevMessage(Guid Id, string From, IReadOnlyList<string>? To, string Subject, DateTime ReceivedDate);
