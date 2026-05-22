using AuthenticationService.Services;
using AuthenticationService.Shared.Models;
using AwesomeAssertions;

namespace AuthenticationService.Tests.Services;

/// <summary>
/// <see cref="RefreshResult"/> is a discriminated union — the controller pattern-matches on the
/// concrete subtype. Tests pin the four cases are mutually distinct types with the expected payloads.
/// </summary>
public class RefreshResultTests
{
    [Fact]
    public void Success_CarriesIssuedToken()
    {
        // arrange
        var token = new Token { Type = "Bearer", Value = "v" };

        // act
        var result = new RefreshResult.Success(token);

        // assert
        result.Token.Should().BeSameAs(token);
    }

    [Fact]
    public void NotFound_HasNoPayload()
    {
        // arrange — NotFound is a marker case; equality is structural so the controller can rely on the type alone.
        var result = new RefreshResult.NotFound();

        // act + assert
        result.Should().Be(new RefreshResult.NotFound());
    }

    [Fact]
    public void Expired_HasNoPayload()
    {
        // act + assert
        new RefreshResult.Expired().Should().Be(new RefreshResult.Expired());
    }

    [Fact]
    public void Reused_CarriesFamilyId()
    {
        // arrange — Reused includes FamilyId so the controller can log "we revoked family X due to reuse."
        var familyId = Guid.NewGuid();

        // act
        var result = new RefreshResult.Reused(familyId);

        // assert
        result.FamilyId.Should().Be(familyId);
    }

    [Fact]
    public void EveryCase_IsItsOwnType_AndAssignableToBase()
    {
        // arrange
        RefreshResult success = new RefreshResult.Success(new Token { Type = "Bearer", Value = "v" });
        RefreshResult notFound = new RefreshResult.NotFound();
        RefreshResult expired = new RefreshResult.Expired();
        RefreshResult reused = new RefreshResult.Reused(Guid.Empty);

        // act + assert
        success.Should().BeOfType<RefreshResult.Success>();
        notFound.Should().BeOfType<RefreshResult.NotFound>();
        expired.Should().BeOfType<RefreshResult.Expired>();
        reused.Should().BeOfType<RefreshResult.Reused>();

        // Two equal-by-value cases of different types must not compare equal.
        ((object)notFound).Should().NotBe(expired);
    }
}
