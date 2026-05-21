using System.Net;
using System.Net.Http.Headers;

namespace AuthenticationService.TokenClientLib;

/// <summary>
/// <see cref="DelegatingHandler"/> that stamps <c>Authorization: Bearer &lt;token&gt;</c>
/// on outgoing requests. On a downstream 401 with
/// <c>WWW-Authenticate: Bearer error="invalid_token"</c> (RFC 6750 §3), invalidates the
/// cached token and retries once. A second 401 bubbles up unchanged.
/// </summary>
public class ServiceTokenHandler : DelegatingHandler
{
    private readonly IServiceTokenProvider _provider;
    private readonly string _audience;
    private readonly IReadOnlyList<string> _scopes;

    /// <summary>
    /// Creates a handler bound to the given audience + scopes.
    /// </summary>
    public ServiceTokenHandler(IServiceTokenProvider provider, string audience, IReadOnlyList<string> scopes)
    {
        _provider = provider;
        _audience = audience;
        _scopes = scopes;
    }

    /// <inheritdoc />
    protected override async Task<HttpResponseMessage> SendAsync(
        HttpRequestMessage request, CancellationToken cancellationToken)
    {
        await StampAuthorizationHeaderAsync(request, cancellationToken);
        var response = await base.SendAsync(request, cancellationToken);

        // Other 401s (auth-policy denial, etc.) pass through — refresh wouldn't fix them.
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

    // True iff response carries WWW-Authenticate: Bearer error="invalid_token" (RFC 6750 §3).
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
