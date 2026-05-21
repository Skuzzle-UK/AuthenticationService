using System.Text.RegularExpressions;

namespace AuthenticationService.IntegrationTests;

/// <summary>
/// Plucks URLs out of email bodies. Auth service emails embed plain-text URLs (no HTML
/// anchor tags), so a basic <c>https?://</c> pattern is enough.
/// </summary>
public static partial class MailLinkExtractor
{
    private static readonly Regex UrlPattern = UrlPatternRegex();

    /// <summary>
    /// All absolute URLs found in <paramref name="body"/>, in order of appearance.
    /// Trailing sentence punctuation is stripped so values like <c>email=alice@example.com.</c>
    /// don't leak the dot into the URL.
    /// </summary>
    public static IEnumerable<Uri> ExtractUrls(string body)
    {
        foreach (Match m in UrlPattern.Matches(body))
        {
            var trimmed = m.Value.TrimEnd('.', ',', ';', ':', '!', '?', ')', ']', '}', '\'', '"');
            if (Uri.TryCreate(trimmed, UriKind.Absolute, out var uri))
            {
                yield return uri;
            }
        }
    }

    /// <summary>
    /// First URL whose absolute form contains <paramref name="substring"/>
    /// (case-insensitive). Aspire allocates random ports per run, so callers match on
    /// path fragments rather than full URLs.
    /// </summary>
    public static Uri? FindLinkContaining(string body, string substring)
    {
        return ExtractUrls(body).FirstOrDefault(
            u => u.AbsoluteUri.Contains(substring, StringComparison.OrdinalIgnoreCase));
    }

    [GeneratedRegex(@"https?://[^\s""<>]+", RegexOptions.IgnoreCase | RegexOptions.Compiled, "en-GB")]
    private static partial Regex UrlPatternRegex();
}
