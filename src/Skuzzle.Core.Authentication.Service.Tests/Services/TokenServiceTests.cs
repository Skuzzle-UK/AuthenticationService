using FluentAssertions;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Skuzzle.Core.Authentication.Lib.Models;
using Skuzzle.Core.Authentication.Service.Services;
using Skuzzle.Core.Authentication.Service.Settings;

namespace Skuzzle.Core.Authentication.Service.Tests.Services;

public class TokenServiceTests
{
    private readonly IMemoryCache _refreshTokenCache;
    
    private TokenService _sut;

    private readonly User _validUser;
    private readonly int _ttl;
    private readonly int _refreshTtl;

    public TokenServiceTests()
    {
        _ttl = 300;
        _refreshTtl = 1800;

        var services = new ServiceCollection();
        services.AddMemoryCache();
        var serviceProvider = services.BuildServiceProvider();

        _refreshTokenCache = serviceProvider.GetService<IMemoryCache>()!;

        _validUser = new User()
        {
            Username = "Username",
            Email = "email@address.com",
            Hash = [],
            Salt = []
        };

        var settings = Options.Create(
            new JwtSettings()
            {
                Audience = "audience",
                Issuer = "issuer",
                Key = "This is a sample secret key - please don't use in production environment.'",
                TtlSeconds = _ttl,
                RefreshTtlSeconds = _refreshTtl
            });

        _sut = new TokenService(_refreshTokenCache, settings);
    }

    [Fact]
    public void GetNewToken_GivenUser_SetsTokenInCacheReturnsValidTokenWithClaims()
    {
        // arrange
        var now = DateTimeOffset.UtcNow;

        // act
        var result = _sut.GetNewToken(_validUser);

        var cacheResult = _refreshTokenCache.TryGetValue(_validUser.Id, out _);

        var validateResult = _sut.ValidateToken(result.AccessToken, false);
        var userIdClaim = validateResult.Value!.FindFirst("UserId");
        var outputUserId = Guid.Parse(userIdClaim!.Value);

        // assert
        result.Should().BeOfType<Token>();
        result.UserId.Should().Be(_validUser.Id);
        result.AccessToken.Should().NotBeNullOrEmpty();
        result.RefreshToken.Should().NotBeNullOrEmpty();
        result.ExpiresAt.Should().BeAfter(now.AddSeconds(_ttl - 1));
        result.RefreshExpiresAt.Should().BeAfter(now.AddSeconds(_refreshTtl - 1));
        
        cacheResult.Should().BeTrue();

        validateResult.Value!.Claims.Should().HaveCountGreaterThan(1);
        outputUserId.Should().Be(_validUser.Id);
    }

    [Fact]
    public void RefreshToken_GivenInvalidUser_ReturnsNull()
    {
        // arrange
        var invalidUser = new User()
        {
            Username = "invalidUser",
            Email = "email@address.com",
            Hash = [],
            Salt = []
        };

        var getNewResult = _sut.GetNewToken(_validUser);

        // act
        var result = _sut.RefreshToken(invalidUser, getNewResult.RefreshToken!);

        // assert
        result.Should().BeNull();
    }

    [Fact]
    public void RefreshToken_GivenValidUserButInvalidRefreshToken_RemovesCachedRefreshTokenForUserAndReturnsNull()
    {
        // arrange
        var getNewResult = _sut.GetNewToken(_validUser);

        // act
        var result = _sut.RefreshToken(_validUser, "invalidRefreshToken");
        var existsInCache = _refreshTokenCache.TryGetValue(_validUser.Id, out _);

        // assert
        result.Should().BeNull();
        existsInCache.Should().BeFalse();
    }

    [Fact]
    public void RefreshToken_GivenValidUserAndRefreshToken_ReturnsNewToken()
    {
        // arrange
        var now = DateTimeOffset.UtcNow;
        var getNewResult = _sut.GetNewToken(_validUser);

        // act
        var result = _sut.RefreshToken(_validUser, getNewResult.RefreshToken!);

        // assert
        result.Should().BeOfType<Token>();
        result!.UserId.Should().Be(_validUser.Id);
        result.AccessToken.Should().NotBeNullOrEmpty();
        result.RefreshToken.Should().NotBeNullOrEmpty();
        result.ExpiresAt.Should().BeAfter(now.AddSeconds(_ttl - 1));
        result.RefreshExpiresAt.Should().BeAfter(now.AddSeconds(_refreshTtl - 1));
    }

    [Fact]
    public void ValidateToken_ValidateLifetimeTrueGivenValidButExpiredToken_ReturnsFailure()
    {
        // arrange
        var settings = Options.Create(
            new JwtSettings()
            {
                Audience = "audience",
                Issuer = "issuer",
                Key = "This is a sample secret key - please don't use in production environment.'",
                TtlSeconds = -1000, // 1000 seconds in past due to default 5 min clock skew allowance
                RefreshTtlSeconds = -1000
            });

        _sut = new TokenService(_refreshTokenCache, settings);

        var getNewResult = _sut.GetNewToken(_validUser);

        // act
        var result = _sut.ValidateToken(getNewResult.AccessToken, true);

        // assert
        result.IsFailure.Should().BeTrue();
    }

    [Fact]
    public void ValidateToken_ValidateLifetimeFalseGivenValidButExpiredToken_ReturnsSuccess()
    {
        // arrange
        var settings = Options.Create(
            new JwtSettings()
            {
                Audience = "audience",
                Issuer = "issuer",
                Key = "This is a sample secret key - please don't use in production environment.'",
                TtlSeconds = -1000, // 1000 seconds in past due to default 5 min clock skew allowance
                RefreshTtlSeconds = -1000
            });

        _sut = new TokenService(_refreshTokenCache, settings);

        var getNewResult = _sut.GetNewToken(_validUser);

        // act
        var result = _sut.ValidateToken(getNewResult.AccessToken, false);

        // assert
        result.IsSuccess.Should().BeTrue();
    }

    [Fact]
    public void ValidateToken_ValidateLifetimeTrueGivenValidToken_ReturnsSuccess()
    {
        // arrange
        var settings = Options.Create(
            new JwtSettings()
            {
                Audience = "audience",
                Issuer = "issuer",
                Key = "This is a sample secret key - please don't use in production environment.'",
                TtlSeconds = 1000, // 1000 seconds in future to ensure token still valid under test
                RefreshTtlSeconds = 1000
            });

        _sut = new TokenService(_refreshTokenCache, settings);

        var getNewResult = _sut.GetNewToken(_validUser);

        // act
        var result = _sut.ValidateToken(getNewResult.AccessToken, true);

        // assert
        result.IsSuccess.Should().BeTrue();
    }

    [Fact]
    public void ValidateToken_ValidateLifetimeFalseGivenValidToken_ReturnsSuccess()
    {
        // arrange
        var settings = Options.Create(
            new JwtSettings()
            {
                Audience = "audience",
                Issuer = "issuer",
                Key = "This is a sample secret key - please don't use in production environment.'",
                TtlSeconds = 1000, // 1000 seconds in future to ensure token still valid under test
                RefreshTtlSeconds = 1000
            });

        _sut = new TokenService(_refreshTokenCache, settings);

        var getNewResult = _sut.GetNewToken(_validUser);

        // act
        var result = _sut.ValidateToken(getNewResult.AccessToken, false);

        // assert
        result.IsSuccess.Should().BeTrue();
    }

    [Fact]
    public void ValidateToken_GivenInvalidToken_ReturnsFail()
    {
        // arrange
        var settings = Options.Create(
            new JwtSettings()
            {
                Audience = "audience",
                Issuer = "issuer",
                Key = "This is a sample secret key - please don't use in production environment.'",
                TtlSeconds = 1000, // 1000 seconds in future to ensure token still valid under test
                RefreshTtlSeconds = 1000
            });

        _sut = new TokenService(_refreshTokenCache, settings);

        var getNewResult = _sut.GetNewToken(_validUser);

        // act
        var result = _sut.ValidateToken("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c", true);

        // assert
        result.IsFailure.Should().BeTrue();
    }
}
