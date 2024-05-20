using FluentAssertions;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Primitives;
using Skuzzle.Core.Authentication.Lib.Models;
using Skuzzle.Core.Authentication.Service.Extensions;

namespace Skuzzle.Core.Authentication.Service.Tests.Extensions;

public class IFormCollectionExtensionsTests
{
    [Fact]
    public void ToAuthenticationRequest_InvalidGrantType_ReturnsNull()
    {
        // arrange
        var formCollection = new FormCollection(
            new Dictionary<string, StringValues>());

        // act
        var result = formCollection.ToAuthenticationRequest();

        // assert
        result.Should().BeNull();
    }

    [Fact]
    public void ToAuthenticationRequest_ValidGrantType_ReturnsAuthenticationRequest()
    {
        // arrange
        var formCollection = new FormCollection(
            new Dictionary<string, StringValues>()
            {
                { "grant_type", "password" }
            });

        // act
        var result = formCollection.ToAuthenticationRequest();

        // assert
        result.Should().BeOfType<AuthenticationRequest?>();
        result.Should().NotBeNull();
    }
}
