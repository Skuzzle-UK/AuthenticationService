using FluentAssertions;
using Skuzzle.Core.Authentication.Service.Extensions;

namespace Skuzzle.Core.Authentication.Service.Tests.Services;

public class PasswordHashServiceTests
{
    private readonly PasswordHashService _sut = new();

    [Theory]
    [InlineData("")]
    [InlineData("password")]
    [InlineData("123947foinwf")]
    public void Create_GivenAnyString_ReturnsHashAndSaltByteArrays(string input)
    {
        // arrange

        // act
        var result = _sut.Create(input);

        // assert
        result.Should().BeOfType<ValueTuple<byte[], byte[]>>();
    }

    [Fact]
    public void Verify_PasswordMatchesHashAndSalt_ReturnsTrue()
    {
        // arrange
        var password = "SomePassword";
        var hash = "lsOrbAlOgFSIEl1ZgFDgMXa4knLklHxh9x1RCNxJ/GxlzjBkzZtXZCctHKJM4AIq4Th0yvcyryfdKnuDpI8xag==";
        var salt = "J9zY0BC3oY0d45IGGK62IgGGy6TOotE0VGSbA3ksLqNWo7JFZjVGeBhthnrSxRViogu7OChH9h/07CqDg4j9gxnduGwBHKqmCpc3Gx2piGiCzMVfZvHHePs3WjOAenlQnCh4rNqG/8AcyaiLyTAWJtElQTcIjvp5KPWTLbGZWIw=";

        // act
        var result = _sut.Verify(password, Convert.FromBase64String(hash), Convert.FromBase64String(salt));

        // assert
        result.Should().BeTrue();
    }

    [Fact]
    public void Verify_PasswordDoesntMatchHashAndSalt_ReturnsFalse()
    {
        // arrange
        var password = "SomeIncorrectPassword";
        var hash = "lsOrbAlOgFSIEl1ZgFDgMXa4knLklHxh9x1RCNxJ/GxlzjBkzZtXZCctHKJM4AIq4Th0yvcyryfdKnuDpI8xag==";
        var salt = "J9zY0BC3oY0d45IGGK62IgGGy6TOotE0VGSbA3ksLqNWo7JFZjVGeBhthnrSxRViogu7OChH9h/07CqDg4j9gxnduGwBHKqmCpc3Gx2piGiCzMVfZvHHePs3WjOAenlQnCh4rNqG/8AcyaiLyTAWJtElQTcIjvp5KPWTLbGZWIw=";

        // act
        var result = _sut.Verify(password, Convert.FromBase64String(hash), Convert.FromBase64String(salt));

        // assert
        result.Should().BeFalse();
    }
}
