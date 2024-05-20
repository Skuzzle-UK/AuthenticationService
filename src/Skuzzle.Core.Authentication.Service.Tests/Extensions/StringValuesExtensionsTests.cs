using FluentAssertions;
using Microsoft.Extensions.Primitives;
using Skuzzle.Core.Authentication.Service.Extensions;

namespace Skuzzle.Core.Authentication.Service.Tests.Extensions;

public class StringValuesExtensionsTests
{
    [Theory]
    [MemberData(nameof(StringValuesTestCases), MemberType = typeof(StringValuesExtensionsTests))]
    public void IsNullOrEmptyOrWhiteSpace_TestedValue_ReturnsTrue(StringValues value, bool expectedResult)
    {
        // arrange

        // act
        var result = value.IsNullOrEmptyOrWhiteSpace();

        // assert
        result.Should().Be(expectedResult);
    }

    public static IEnumerable<object[]> StringValuesTestCases
    {
        get
        {
            string? nullstring = null;

            yield return new object[]
                {
                    new StringValues(nullstring),
                    true
                };

            yield return new object[]
                {
                    new StringValues(""),
                    true
                };

            yield return new object[]
                {
                    new StringValues(" "),
                    true
                };

            yield return new object[]
                {
                    new StringValues("abc"),
                    false
                };
        }
    }
}