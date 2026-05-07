using AuthenticationService.Services;
using AuthenticationService.Shared.Models;
using AwesomeAssertions;

namespace AuthenticationService.Tests.Services;

/// <summary>
/// <para><see cref="RefreshResult"/> is a discriminated union: the controller pattern-matches
/// on the concrete subtype to decide the response. The contract is "exactly four cases —
/// don't add new cases without updating callers." These tests pin that contract by
/// constructing each case and verifying its identity + payload, plus pin that the four
/// cases are mutually distinct types.</para>
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

        // assert — Success wraps the new access+refresh pair the controller returns.
        result.Token.Should().BeSameAs(token);
    }

    [Fact]
    public void NotFound_HasNoPayload()
    {
        // arrange / act
        var result = new RefreshResult.NotFound();

        // assert — NotFound is a marker case; equality is structural so two instances
        // compare equal (record semantics). Pinned because controller doesn't read state
        // off of it — relying on the type alone.
        result.Should().Be(new RefreshResult.NotFound());
    }

    [Fact]
    public void Expired_HasNoPayload()
    {
        new RefreshResult.Expired().Should().Be(new RefreshResult.Expired());
    }

    [Fact]
    public void Reused_CarriesFamilyId()
    {
        // arrange — Reused includes the FamilyId so the controller can log "we revoked
        // family X due to reuse." Critical-level SIEM event needs this field.
        var familyId = Guid.NewGuid();

        // act
        var result = new RefreshResult.Reused(familyId);

        // assert
        result.FamilyId.Should().Be(familyId);
    }

    [Fact]
    public void EveryCase_IsItsOwnType_AndAssignableToBase()
    {
        // arrange — pattern-matching on RefreshResult requires the concrete cases all
        // be RefreshResult subtypes AND distinct from each other. Pinned to catch any
        // refactor that accidentally collapses two cases or moves a case out of the
        // hierarchy.
        RefreshResult success = new RefreshResult.Success(new Token { Type = "Bearer", Value = "v" });
        RefreshResult notFound = new RefreshResult.NotFound();
        RefreshResult expired = new RefreshResult.Expired();
        RefreshResult reused = new RefreshResult.Reused(Guid.Empty);

        // assert
        success.Should().BeOfType<RefreshResult.Success>();
        notFound.Should().BeOfType<RefreshResult.NotFound>();
        expired.Should().BeOfType<RefreshResult.Expired>();
        reused.Should().BeOfType<RefreshResult.Reused>();

        // Distinct types — two equal-by-value cases of different types do not compare equal.
        ((object)notFound).Should().NotBe(expired);
    }
}
