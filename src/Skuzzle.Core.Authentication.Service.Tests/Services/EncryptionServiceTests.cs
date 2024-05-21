using FluentAssertions;
using Microsoft.Extensions.Options;
using Skuzzle.Core.Authentication.Lib.Models;
using Skuzzle.Core.Authentication.Service.Services;
using Skuzzle.Core.Authentication.Service.Settings;

namespace Skuzzle.Core.Authentication.Service.Tests.Services;

public class EncryptionServiceTests
{
    private readonly EncryptionService _sut;

    public EncryptionServiceTests()
    {
        var settings = Options.Create(
            new EncryptionSettings() {
                InitialisationVector = Convert.FromBase64String("Z+9qB5tsxD0Bp5Z1rTbMNQ=="),
                Key = Convert.FromBase64String("iXou/QmtMYwm3eiik45LaNWVU+Q8awyEAqk1qBKo9A0="),
                Iterations = 1,
            });

        _sut = new EncryptionService(settings);
    }

    [Fact]
    public void Decrypt_EncryptedStringInParams_ReturnsDeserializedObject()
    {
        // arrange
        var input = "+n5uSp3fAwf2Pr80HN9FfthnRJzIriYGU0jbWzued2E=";

        // act
        var result = _sut.Decrypt<string>(input);

        // assert
        result.Should().BeOfType<string>();
        result.Should().Be("A string should do");
    }

    [Fact]
    public void Decrypt_EncryptedStringInParams_ReturnsComplexDeserializedObject()
    {
        // arrange
        var input = "ORGJcvoabplyxMrQ0GGeZyIGDOA0otLDYK7VlqPCyWt1uf1Ax46GWf3dmO/VSRrOOHMaJRStFKL6K4NmLAEB8mFuO1mLG97rOQ5b9aWxBE9/HACuf80EyXfIC242fE7wrPtlo6tARyAVrsvOrx9d08AhaW1v5zQNCAdsy0mz5AObdirob47+NAAhlPjCWXEemheyY/3WSthHqsTECEWhT/0D04L0yyBmA2dsPoPG4uHl1wUuI8VySyOQPyjKAvyP";
        
        var expectedOutput = new User()
        {
            Username = "AUserName",
            Hash = [],
            Salt = [],
            Email = "email@somewhere.com"
        };

        // act
        var result = _sut.Decrypt<User>(input);

        // assert
        result.Should().BeOfType<User>();
        result!.Username.Should().Be(expectedOutput.Username);
        result!.Email.Should().Be(expectedOutput.Email);
    }

    [Fact]
    public void Decrypt_NotEncryptedStringInParams_ReturnsNull()
    {
        // arrange
        var input = "NotAnEncyryptedString";

        // act
        var result = _sut.Decrypt<string>(input);

        // assert
        result.Should().BeNull();
    }

    [Fact]
    public void Decrypt_InvalidEncryptedStringForType_ReturnsDefault()
    {
        // arrange
        var input = "+n5uSp3fAwf2Pr80HN9FfthnRJzIriYGU0jbWzued2E=";

        // act
        var result = _sut.Decrypt<User>(input);

        // assert
        result.Should().BeNull();
    }

    [Fact]
    public void Encrypt_GivenSimpleType_ReturnsCorrectEncryptedString()
    {
        // arrange
        var simpleType = "A string should do";

        // act
        var result = _sut.Encrypt(simpleType);

        // assert
        result.Should().Be("+n5uSp3fAwf2Pr80HN9FfthnRJzIriYGU0jbWzued2E=");
    }

    [Fact]
    public void Encrypt_GivenComplexType_ReturnsEncryptedString()
    {
        // arrange
        var complexType = new User()
        {
            Username = "AUserName",
            Hash = [],
            Salt = [],
            Email = "email@somewhere.com"
        };

        // act
        var result = _sut.Encrypt(complexType);

        // assert
        result.Should().BeOfType<string>();
    }

    [Fact]
    public void Encrypt_GivenComplexType_ReturnedSringCanBeDecrypted()
    {
        // arrange
        var complexType = new User()
        {
            Username = "AUserName",
            Hash = [],
            Salt = [],
            Email = "email@somewhere.com"
        };

        // act
        var result = _sut.Encrypt(complexType);
        var decryptedResult = _sut.Decrypt<User>(result);

        // assert
        result.Should().BeOfType<string>();
        decryptedResult.Should().BeOfType<User>();
        decryptedResult.Should().BeEquivalentTo(complexType);
    }
}
