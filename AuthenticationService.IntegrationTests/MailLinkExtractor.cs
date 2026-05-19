using System.Text.RegularExpressions;

namespace AuthenticationService.IntegrationTests;

/// <summary>
/// Plucks URLs out of email bodies using a deliberately permissive regex. Auth service
/// emails embed plain-text URLs (no HTML anchor tags), so a basic <c>https?://</c>
/// pattern is enough.
/// </summary>
public static partial class MailLinkExtractor
{
    private static readonly Regex UrlPattern = UrlPatternRegex();

    /// <summary>
    /// All absolute URLs found in <paramref name="body"/>, in order of appearance.
    /// Strings that match the pattern but fail <see cref="Uri.TryCreate"/> are skipped
    /// (defensive against half-formed matches at the regex boundary).
    ///
    /// <para>Trailing sentence punctuation (<c>.,;:!?)]}'"</c>) is stripped — email bodies
    /// commonly say "click the following link: {url}. If you ..." and the regex's lazy
    /// boundary captures the trailing dot which then ends up inside the URL's last
    /// query-value (visible as <c>email=alice@example.com.</c>). Stripping here keeps the
    /// callers honest without each having to remember to chop punctuation off.</para>
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
    /// First URL in <paramref name="body"/> whose absolute form contains
    /// <paramref name="substring"/> (case-insensitive). Useful for "find the
    /// confirmation link" or "find the reset link" without depending on exact host or
    /// port — Aspire allocates random ports per run, so the URL changes between
    /// invocations.
    /// </summary>
    public static Uri? FindLinkContaining(string body, string substring)
    {
        return ExtractUrls(body).FirstOrDefault(
            u => u.AbsoluteUri.Contains(substring, StringComparison.OrdinalIgnoreCase));
    }

    [GeneratedRegex(@"https?://[^\s""<>]+", RegexOptions.IgnoreCase | RegexOptions.Compiled, "en-GB")]
    private static partial Regex UrlPatternRegex();
}
