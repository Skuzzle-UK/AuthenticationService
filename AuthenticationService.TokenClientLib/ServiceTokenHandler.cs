using System.Net;
using System.Net.Http.Headers;

namespace AuthenticationService.TokenClientLib;

/// <summary>
/// <see cref="DelegatingHandler"/> that stamps <c>Authorization: Bearer &lt;token&gt;</c>
/// on outgoing requests using a token from <see cref="IServiceTokenProvider"/>. One
/// handler per typed client, with audience + scopes baked in at registration time
/// (via <c>AddServiceToken(audience, scopes)</c>).
///
/// <para><b>Stale-token recovery</b>: on a downstream <c>401 Unauthorized</c> with a
/// <c>WWW-Authenticate: Bearer error="invalid_token"</c> hint (RFC 6750 §3), the
/// handler invalidates the cached token and retries the request once with a fresh
/// one. A second 401 means credentials themselves don't work (or some other 401
/// reason that re-fetching can't fix) and bubbles up to the caller as-is.</para>
/// </summary>
public class ServiceTokenHandler : DelegatingHandler
{
    private readonly IServiceTokenProvider _provider;
    private readonly string _audience;
    private readonly IReadOnlyList<string> _scopes;

    public ServiceTokenHandler(IServiceTokenProvider provider, string audience, IReadOnlyList<string> scopes)
    {
        _provider = provider;
        _audience = audience;
        _scopes = scopes;
    }

    protected override async Task<HttpResponseMessage> SendAsync(
        HttpRequestMessage request, CancellationToken cancellationToken)
    {
        await StampAuthorizationHeaderAsync(request, cancellationToken);
        var response = await base.SendAsync(request, cancellationToken);

        // Stale-token retry: only on 401 + RFC 6750 invalid_token hint. Other 401s
        // (auth-policy denial, etc.) pass through unchanged because they're not
        // token-staleness issues a refresh would fix.
        if (response.StatusCode == HttpStatusCode.Unauthorized && IndicatesInvalidToken(response))
        {
            response.Dispose();
            _provider.Invalidate(_audience, _scopes);

            await StampAuthorizationHeaderAsync(request, cancellationToken);
            response = await base.SendAsync(request, cancellationToken);
        }

        return response;
    }

    private async Task StampAuthorizationHeaderAsync(HttpRequestMessage request, CancellationToken ct)
    {
        var token = await _provider.GetTokenAsync(_audience, _scopes, ct);
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
    }

    /// <summary>
    /// Returns true iff the response carries <c>WWW-Authenticate: Bearer error="invalid_token"</c>
    /// per RFC 6750 §3. A 401 without this hint is treated as a permanent auth failure
    /// (the caller is genuinely not allowed, not just holding a stale token).
    /// </summary>
    private static bool IndicatesInvalidToken(HttpResponseMessage response)
    {
        foreach (var header in response.Headers.WwwAuthenticate)
        {
            if (!string.Equals(header.Scheme, "Bearer", StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }
            var parameter = header.Parameter;
            if (!string.IsNullOrEmpty(parameter)
                && parameter.Contains("error=\"invalid_token\"", StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
        }
        return false;
    }
}
