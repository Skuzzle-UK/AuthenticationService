using AuthenticationService.Entities;
using AuthenticationService.Services;
using AuthenticationService.Storage;
using AuthenticationService.Tests.Helpers;
using AwesomeAssertions;
using Microsoft.AspNetCore.Identity;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;

namespace AuthenticationService.Tests.Services;

/// <summary>
/// Drives <see cref="ClientService"/> against SQLite-InMemory. Verifies the SQL-translatable query shapes
/// plus the secret-hash round-trip and the idempotency contracts on admin-side methods.
/// </summary>
public class ClientServiceTests : IDisposable
{
    [Fact]
    public async Task FindActiveAsync_UnknownClient_ReturnsNull()
    {
        // arrange
        var (svc, _) = BuildService();

        // act
        var result = await svc.FindActiveAsync("ghost", CancellationToken.None);

        // assert
        result.Should().BeNull();
    }

    [Fact]
    public async Task FindActiveAsync_DisabledClient_ReturnsNullSameAsUnknown()
    {
        // arrange — token endpoint can't reveal whether a client id exists when disabled; only that auth failed.
        var (svc, db) = BuildService();
        await SeedClientAsync(db, id: "disabled", isDisabled: true);

        // act
        var result = await svc.FindActiveAsync("disabled", CancellationToken.None);

        // assert
        result.Should().BeNull();
    }

    [Fact]
    public async Task FindActiveAsync_ActiveClient_ReturnsRow()
    {
        // arrange
        var (svc, db) = BuildService();
        await SeedClientAsync(db, id: "active", isDisabled: false);

        // act
        var result = await svc.FindActiveAsync("active", CancellationToken.None);

        // assert
        result.Should().NotBeNull();
        result!.Id.Should().Be("active");
    }

    [Fact]
    public async Task VerifySecret_RoundTrip_AcceptsHashedSecret()
    {
        // arrange
        var (svc, _) = BuildService();
        var hasher = new PasswordHasher<Client>();
        var client = new Client { Id = "c", Name = "Test", ClientSecretHash = "" };
        client.ClientSecretHash = hasher.HashPassword(client, "the-secret");

        // act + assert
        svc.VerifySecret(client, "the-secret").Should().BeTrue();
    }

    [Fact]
    public async Task VerifySecret_WrongSecret_Rejects()
    {
        // arrange
        var (svc, _) = BuildService();
        var hasher = new PasswordHasher<Client>();
        var client = new Client { Id = "c", Name = "Test", ClientSecretHash = "" };
        client.ClientSecretHash = hasher.HashPassword(client, "the-secret");

        // act + assert
        svc.VerifySecret(client, "different-secret").Should().BeFalse();
    }

    [Fact]
    public async Task HasScopeAsync_TupleExists_ReturnsTrue()
    {
        // arrange
        var (svc, db) = BuildService();
        await SeedClientAsync(db, id: "c", scopes: [("inventory-api", "inventory.read")]);

        // act + assert
        (await svc.HasScopeAsync("c", "inventory-api", "inventory.read", CancellationToken.None))
            .Should().BeTrue();
    }

    [Fact]
    public async Task HasScopeAsync_DifferentAudience_ReturnsFalse()
    {
        // arrange — audience + scope checked as a tuple: (inventory-api, inventory.read) doesn't grant (orders-api, inventory.read).
        var (svc, db) = BuildService();
        await SeedClientAsync(db, id: "c", scopes: [("inventory-api", "inventory.read")]);

        // act + assert
        (await svc.HasScopeAsync("c", "orders-api", "inventory.read", CancellationToken.None))
            .Should().BeFalse();
    }

    [Fact]
    public async Task TouchLastUsedAsync_StampsTimestamp()
    {
        // arrange
        var (svc, db) = BuildService();
        await SeedClientAsync(db, id: "c");

        // act
        await svc.TouchLastUsedAsync("c", CancellationToken.None);

        // assert
        var refreshed = await db.Clients.AsNoTracking().FirstAsync(c => c.Id == "c");
        refreshed.LastUsedAt.Should().NotBeNull(
            because: "TouchLastUsedAsync exists to stamp LastUsedAt after a successful token issue.");
    }

    [Fact]
    public async Task CreateAsync_HashesSecretAndAddsScopes()
    {
        // arrange
        var (svc, db) = BuildService();

        // act
        var client = await svc.CreateAsync(
            clientId: "new-client",
            name: "New",
            rawSecret: "raw-secret-value",
            description: "demo",
            scopes: new[] { ("inventory-api", "inventory.read"), ("orders-api", "orders.write") },
            CancellationToken.None);

        // assert
        client.ClientSecretHash.Should().NotBe("raw-secret-value",
            because: "the plaintext secret must never be persisted; only its hash.");
        svc.VerifySecret(client, "raw-secret-value").Should().BeTrue(
            because: "the stored hash must round-trip with the supplied plaintext.");

        var scopeRows = await db.ClientScopes.AsNoTracking()
            .Where(s => s.ClientId == "new-client")
            .ToListAsync();
        scopeRows.Should().HaveCount(2);
    }

    [Fact]
    public async Task RotateSecretAsync_UnknownClient_ReturnsNull()
    {
        // arrange
        var (svc, _) = BuildService();

        // act
        var result = await svc.RotateSecretAsync("ghost", "any-new-secret", CancellationToken.None);

        // assert
        result.Should().BeNull();
    }

    [Fact]
    public async Task RotateSecretAsync_HappyPath_OverwritesHashAndOldSecretStopsWorking()
    {
        // arrange
        var (svc, db) = BuildService();
        await SeedClientAsync(db, id: "c", rawSecret: "old-secret");

        // act
        var rotated = await svc.RotateSecretAsync("c", "new-secret", CancellationToken.None);

        // assert
        rotated.Should().NotBeNull();
        svc.VerifySecret(rotated!, "new-secret").Should().BeTrue();
        svc.VerifySecret(rotated!, "old-secret").Should().BeFalse(
            because: "rotation must invalidate the previous secret.");
    }

    [Fact]
    public async Task DisableAsync_FlipsFlag_AndIsIdempotent()
    {
        // arrange
        var (svc, db) = BuildService();
        await SeedClientAsync(db, id: "c", isDisabled: false);

        // act + assert
        (await svc.DisableAsync("c", CancellationToken.None)).Should().BeTrue(
            because: "first call disables the client.");
        (await svc.DisableAsync("c", CancellationToken.None)).Should().BeFalse(
            because: "second call is a no-op — already-disabled clients don't get re-stamped.");

        var refreshed = await db.Clients.AsNoTracking().FirstAsync(c => c.Id == "c");
        refreshed.IsDisabled.Should().BeTrue();
    }

    [Fact]
    public async Task AddScopeAsync_NewTuple_AddsRowReturnsTrue()
    {
        // arrange
        var (svc, db) = BuildService();
        await SeedClientAsync(db, id: "c");

        // act
        var added = await svc.AddScopeAsync("c", "inventory-api", "inventory.read", CancellationToken.None);

        // assert
        added.Should().BeTrue();
        (await db.ClientScopes.AnyAsync(s => s.ClientId == "c" && s.Scope == "inventory.read"))
            .Should().BeTrue();
    }

    [Fact]
    public async Task AddScopeAsync_DuplicateTuple_NoOpReturnsFalse()
    {
        // arrange — unique index on (ClientId, Audience, Scope) would throw; service preempts with an existence check.
        var (svc, db) = BuildService();
        await SeedClientAsync(db, id: "c", scopes: [("inventory-api", "inventory.read")]);

        // act
        var added = await svc.AddScopeAsync("c", "inventory-api", "inventory.read", CancellationToken.None);

        // assert
        added.Should().BeFalse();
        (await db.ClientScopes.CountAsync(s => s.ClientId == "c")).Should().Be(1,
            because: "duplicate adds must not create a second row.");
    }

    [Fact]
    public async Task RemoveScopeAsync_ExistingTuple_DeletesReturnsTrue()
    {
        // arrange
        var (svc, db) = BuildService();
        await SeedClientAsync(db, id: "c", scopes: [("inventory-api", "inventory.read")]);

        // act
        var removed = await svc.RemoveScopeAsync("c", "inventory-api", "inventory.read", CancellationToken.None);

        // assert
        removed.Should().BeTrue();
        (await db.ClientScopes.AnyAsync(s => s.ClientId == "c")).Should().BeFalse();
    }

    [Fact]
    public async Task RemoveScopeAsync_NonExistentTuple_ReturnsFalse()
    {
        // arrange
        var (svc, _) = BuildService();

        // act
        var removed = await svc.RemoveScopeAsync("ghost", "audience", "scope", CancellationToken.None);

        // assert
        removed.Should().BeFalse();
    }

    // ─── helpers ────────────────────────────────────────────────────────────────────

    private (ClientService service, DatabaseContext db) BuildService()
    {
        var connection = new SqliteConnection("DataSource=:memory:");
        connection.Open();
        _connections.Add(connection);

        var options = new DbContextOptionsBuilder<DatabaseContext>().UseSqlite(connection).Options;
        var db = new TestDatabaseContext(options);
        db.Database.EnsureCreated();
        _contexts.Add(db);

        var hasher = new PasswordHasher<Client>();
        return (new ClientService(db, hasher), db);
    }

    private static async Task SeedClientAsync(
        DatabaseContext db,
        string id,
        bool isDisabled = false,
        string rawSecret = "secret",
        (string Audience, string Scope)[]? scopes = null)
    {
        var hasher = new PasswordHasher<Client>();
        var client = new Client
        {
            Id = id,
            Name = $"Test {id}",
            IsDisabled = isDisabled,
            ClientSecretHash = "",
        };
        client.ClientSecretHash = hasher.HashPassword(client, rawSecret);
        if (scopes is not null)
        {
            foreach (var (audience, scope) in scopes)
            {
                client.Scopes.Add(new ClientScope { ClientId = id, Audience = audience, Scope = scope });
            }
        }
        db.Clients.Add(client);
        await db.SaveChangesAsync();
    }

    private readonly List<SqliteConnection> _connections = new();
    private readonly List<DatabaseContext> _contexts = new();

    public void Dispose()
    {
        foreach (var ctx in _contexts) { try { ctx.Dispose(); } catch { } }
        foreach (var conn in _connections) { try { conn.Dispose(); } catch { } }
        GC.SuppressFinalize(this);
    }
}
