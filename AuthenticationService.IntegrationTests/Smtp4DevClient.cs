using System.Net.Http.Json;

namespace AuthenticationService.IntegrationTests;

/// <summary>
/// Thin client for smtp4dev's HTTP API. Used by integration tests to assert that the
/// auth service sent the expected emails and to pull links out of message bodies. The
/// underlying <see cref="HttpClient"/> is the one Aspire creates pointing at the
/// smtp4dev container's http endpoint.
/// </summary>
public sealed class Smtp4DevClient
{
    private readonly HttpClient _client;

    public Smtp4DevClient(HttpClient client)
    {
        _client = client;
    }

    /// <summary>
    /// Lists every message currently in the smtp4dev inbox. Returns the most recent
    /// first so a test that just sent one email can grab <c>[0]</c> without juggling
    /// dates.
    /// </summary>
    public async Task<IReadOnlyList<Smtp4DevMessage>> ListMessagesAsync(CancellationToken ct = default)
    {
        var page = await _client.GetFromJsonAsync<MessagesPage>(
            "/api/Messages?pageSize=100&sortColumn=receivedDate&sortIsDescending=true",
            ct);
        return page?.Results ?? [];
    }

    /// <summary>
    /// Returns the HTML body of the message. Auth service emails are plain-text wrapped
    /// in an html part — the body is just the original string verbatim, which is fine
    /// for link extraction via <see cref="MailLinkExtractor"/>.
    /// </summary>
    public async Task<string> GetMessageHtmlAsync(Guid messageId, CancellationToken ct = default)
    {
        var response = await _client.GetAsync($"/api/Messages/{messageId}/html", ct);
        response.EnsureSuccessStatusCode();
        return await response.Content.ReadAsStringAsync(ct);
    }

    /// <summary>
    /// Wipes every message from the inbox. Tests call this in their setup so assertions
    /// never see stale messages from earlier tests in the same fixture lifetime.
    /// </summary>
    public async Task ClearAsync(CancellationToken ct = default)
    {
        var response = await _client.DeleteAsync("/api/Messages/*", ct);
        response.EnsureSuccessStatusCode();
    }

    /// <summary>
    /// Polls until a message addressed to <paramref name="toEmail"/> arrives, or
    /// <paramref name="timeout"/> passes. Returns null on timeout. Email delivery via
    /// the QueuedEmailService dispatcher is sub-second under normal load but worth a
    /// generous timeout in case CI is chugging.
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
/// Subset of smtp4dev's message-list shape used by integration tests. The full schema
/// has more fields (attachmentCount, isUnread, etc.) we don't need. <see cref="To"/> is
/// a list because smtp4dev's API returns recipients as a JSON array — even when there's
/// only one.
/// </summary>
public sealed record Smtp4DevMessage(Guid Id, string From, IReadOnlyList<string>? To, string Subject, DateTime ReceivedDate);
