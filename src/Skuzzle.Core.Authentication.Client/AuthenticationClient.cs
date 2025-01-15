using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Options;
using Polly;
using Polly.Retry;
using Skuzzle.Core.Authentication.Client.Settings;
using Skuzzle.Core.Authentication.Lib.Dtos;
using Skuzzle.Core.Authentication.Lib.Models;
using Skuzzle.Core.Lib.ResultClass;
using System.Net;
using System.Text;
using System.Text.Json;

namespace Skuzzle.Core.Authentication.Client;

public class AuthenticationClient : IAuthenticationClient
{
    private readonly IHttpClientFactory _httpClientFactory;
    private readonly IMemoryCache _tokensCache;

    private readonly AuthenticationClientSettings _settings;
    private readonly AsyncRetryPolicy<HttpResponseMessage> _retryPolicy;

    public AuthenticationClient(
        IHttpClientFactory httpClientFactory,
        IMemoryCache tokensCache,
        IOptions<AuthenticationClientSettings> settings)
    {
        _httpClientFactory = httpClientFactory;
        _tokensCache = tokensCache;

        _settings = new()
        {
            LoginUrl = settings.Value.LoginUrl,
            RefreshUrl = settings.Value.RefreshUrl,
            RegisterUrl = settings.Value.RegisterUrl,
            RetryCount = settings.Value.RetryCount is not null ? settings.Value.RetryCount : 3,
            RetryDelay = settings.Value.RetryDelay is not null ? settings.Value.RetryDelay : 10,
            DefaultRefreshExpiry = settings.Value.DefaultRefreshExpiry is not null ? settings.Value.DefaultRefreshExpiry : 3600
        };

        _retryPolicy = Policy
            .Handle<HttpRequestException>()
            .OrResult<HttpResponseMessage>(r => !r.IsSuccessStatusCode && !IsExcludedStatusCode(r.StatusCode))
            .WaitAndRetryAsync(_settings.RetryCount.Value, r => TimeSpan.FromSeconds(_settings.RetryDelay.Value));
    }

    private bool IsExcludedStatusCode(HttpStatusCode statusCode)
    {
        return statusCode == HttpStatusCode.BadRequest
            || statusCode == HttpStatusCode.Unauthorized
            || statusCode == HttpStatusCode.Forbidden
            || statusCode == HttpStatusCode.NotFound
            || statusCode == HttpStatusCode.Conflict
            || statusCode == HttpStatusCode.UnprocessableEntity;
    }

    public async Task<Result> RegisterUserAsync(UserDto user, CancellationToken ct = default)
    {
        using var client = _httpClientFactory.CreateClient();

        var jsonPayload = JsonSerializer.Serialize(user);
        var payload = new StringContent(jsonPayload, Encoding.UTF8, "application/json");

        var response = await _retryPolicy.ExecuteAsync(async cancellationToken =>
        {
            var result = await client.PostAsync(_settings.RegisterUrl, payload, cancellationToken);
            if (IsExcludedStatusCode(result.StatusCode))
            {
                {
                    return result;
                }
            }
                return result.EnsureSuccessStatusCode();
        }, ct);

        return response.IsSuccessStatusCode
            ? Result.Ok()
            : Result.Fail(await response.Content.ReadAsStringAsync(ct));
    }

    public async Task<Result<Token>> GetTokenAsync(Guid userId, CancellationToken ct = default) =>
        await TryGetExistingTokenAsync(userId, ct);

    public async Task<Result<Token>> GetTokenAsync(AuthenticationRequest authRequest, CancellationToken ct = default) =>
        await GetNewTokenAsync(authRequest, ct);

    private async Task<Result<Token>> TryGetExistingTokenAsync(Guid userId, CancellationToken ct)
    {
        if (!_tokensCache.TryGetValue(userId, out Token? token))
        {
            // Request username and password
            return Result.Fail<Token>("No token found for user. Login required.");
        }

        if (token is null)
        {
            // Request username and password
            return Result.Fail<Token>("No token found for user. Login required.");
        }

        if (token.RefreshExpiresAt >= DateTimeOffset.UtcNow)
        {
            // Request username and password
            return Result.Fail<Token>("Refresh token expired. Login required.");
        }

        if (token.ExpiresAt >= DateTimeOffset.UtcNow)
        {
            var newTokenResult = await RefreshTokenFromAuthenticationService(token, ct);
            if (newTokenResult.IsFailure || newTokenResult.Value is null)
            {
                return Result.Fail<Token>(newTokenResult.ErrorMessage);
            }

            token = newTokenResult.Value;
        }

        return Result.Ok(token);
    }

    private async Task<Result<Token>> GetNewTokenAsync(AuthenticationRequest request, CancellationToken ct)
    {
        var result = await RequestNewTokenFromAuthenticationService(request, ct);
        if (result.IsFailure || result.Value is null)
        {
            return Result.Fail<Token>(result.ErrorMessage);
        }

        var token = result.Value;

        if (_tokensCache.TryGetValue(token.UserId, out Token? existingToken))
        {
            _tokensCache.Remove(token.UserId);
        }

        var expiresAt = token.RefreshExpiresAt is not null
            ? token.RefreshExpiresAt
            : DateTimeOffset.UtcNow.AddSeconds(_settings.DefaultRefreshExpiry!.Value);

        _tokensCache.Set(token.UserId, token, expiresAt.Value);

        return Result.Ok(token);
    }

    private async Task<Result<Token>> RequestNewTokenFromAuthenticationService(AuthenticationRequest request, CancellationToken ct)
    {
        using var client = _httpClientFactory.CreateClient();

        var formValues = new List<KeyValuePair<string, string>>
        {
            new KeyValuePair<string, string>("GRANT_TYPE", request.GrantType.ToString()),
            new KeyValuePair<string, string>("USERNAME", request.Username ?? string.Empty),
            new KeyValuePair<string, string>("PASSWORD", request.Password ?? string.Empty)
        };

        var content = new FormUrlEncodedContent(formValues);

        var response = await _retryPolicy.ExecuteAsync(async cancellationToken =>
        {
            var result = await client.PostAsync(_settings.LoginUrl, content, cancellationToken);
            if (result.StatusCode == HttpStatusCode.BadRequest
                || result.StatusCode == HttpStatusCode.Unauthorized
                || result.StatusCode == HttpStatusCode.Forbidden
                || result.StatusCode == HttpStatusCode.NotFound
                || result.StatusCode == HttpStatusCode.Conflict
                || result.StatusCode == HttpStatusCode.UnprocessableEntity)
            {
                {
                    return result;
                }
            }
            return result.EnsureSuccessStatusCode();
        }, ct);

        var jsonResponse = await response.Content.ReadAsStringAsync(ct);

        if (!response.IsSuccessStatusCode)
        {
            return Result.Fail<Token>(jsonResponse);
        }

        var token = JsonSerializer.Deserialize<Token>(jsonResponse);

        if (token is null)
        {
            return Result.Fail<Token>(jsonResponse);
        }

        return Result.Ok(token);
    }

    private async Task<Result<Token>> RefreshTokenFromAuthenticationService(Token oldToken, CancellationToken ct)
    {
        using var client = _httpClientFactory.CreateClient();

        var jsonPayload = JsonSerializer.Serialize(oldToken);
        var payload = new StringContent(jsonPayload, Encoding.UTF8, "application/json");

        var response = await _retryPolicy.ExecuteAsync(async cancellationToken =>
        {
            var result = await client.PostAsync(_settings.RefreshUrl, payload, cancellationToken);
            if (result.StatusCode == HttpStatusCode.BadRequest
                || result.StatusCode == HttpStatusCode.Unauthorized
                || result.StatusCode == HttpStatusCode.Forbidden
                || result.StatusCode == HttpStatusCode.NotFound
                || result.StatusCode == HttpStatusCode.Conflict
                || result.StatusCode == HttpStatusCode.UnprocessableEntity)
            {
                {
                    return result;
                }
            }
            return result.EnsureSuccessStatusCode();
        }, ct);

        var jsonResult = await response.Content.ReadAsStringAsync(ct);

        if (!response.IsSuccessStatusCode)
        {
            return Result.Fail<Token>(jsonResult);
        }

        var newToken = JsonSerializer.Deserialize<Token>(jsonResult);

        if (newToken is null)
        {
            return Result.Fail<Token>(jsonResult);
        }

        return Result.Ok(newToken);
    }
}
