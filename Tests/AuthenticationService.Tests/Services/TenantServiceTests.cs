using AuthenticationService.Entities;
using AuthenticationService.Enums;
using AuthenticationService.Services;
using AuthenticationService.Storage;
using AuthenticationService.Tests.Helpers;
using AuthenticationService.Validators;
using AwesomeAssertions;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging.Abstractions;

namespace AuthenticationService.Tests.Services;

/// <summary>
/// TenantService lifecycle tests. Backed by SQLite in-memory + TestDatabaseContext so
/// the DateTimeOffset and unique-index machinery exercises the same query shape EF
/// will use against the production providers.
/// </summary>
public class TenantServiceTests : IDisposable
{
    private readonly List<SqliteConnection> _connections = [];
    private readonly List<DatabaseContext> _contexts = [];

    public void Dispose()
    {
        foreach (var c in _contexts) c.Dispose();
        foreach (var c in _connections) c.Dispose();
        GC.SuppressFinalize(this);
    }

    [Fact]
    public async Task CreateAsync_ValidName_PersistsTenant()
    {
        // arrange
        var (service, db) = BuildService();

        // act
        var result = await service.CreateAsync("acme", "Acme Corp", "u-1", CancellationToken.None);

        // assert
        result.Should().BeOfType<CreateTenantResult.Success>();
        var success = (CreateTenantResult.Success)result;
        success.Name.Should().Be("acme");

        db.ChangeTracker.Clear();
        var persisted = await db.Tenants.SingleAsync();
        persisted.Name.Should().Be("acme");
        persisted.DisplayName.Should().Be("Acme Corp");
        persisted.Status.Should().Be(TenantStatus.Active);
        persisted.SuspendedAt.Should().BeNull();
        persisted.PendingDeletionAt.Should().BeNull();
    }

    [Fact]
    public async Task CreateAsync_InvalidName_ReturnsValidationFailure()
    {
        // arrange
        var (service, _) = BuildService();

        // act — name starts with a hyphen, fails the regex.
        var result = await service.CreateAsync("-acme", "Acme", "u-1", CancellationToken.None);

        // assert
        result.Should().BeOfType<CreateTenantResult.InvalidName>();
    }

    [Fact]
    public async Task CreateAsync_DuplicateName_ReturnsAlreadyExists()
    {
        // arrange
        var (service, db) = BuildService();
        await service.CreateAsync("acme", "Acme", "u-1", CancellationToken.None);

        // act — attempt the same name again.
        var result = await service.CreateAsync("acme", "Acme Reincarnated", "u-1", CancellationToken.None);

        // assert
        result.Should().BeOfType<CreateTenantResult.NameAlreadyExists>();
        db.ChangeTracker.Clear();
        (await db.Tenants.CountAsync()).Should().Be(1, because: "the duplicate must not be persisted.");
    }

    [Fact]
    public async Task CreateAsync_NameIsLowercased()
    {
        // arrange — input uppercase to verify the canonicalisation step.
        var (service, db) = BuildService();

        // act
        await service.CreateAsync("ACME", "Acme", "u-1", CancellationToken.None);

        // assert
        db.ChangeTracker.Clear();
        var t = await db.Tenants.SingleAsync();
        t.Name.Should().Be("acme", because: "names are normalised to lowercase before persistence.");
    }

    [Fact]
    public async Task SuspendAsync_ActiveTenant_TransitionsToSuspended()
    {
        // arrange
        var (service, db) = BuildService();
        await service.CreateAsync("acme", "Acme", "u-1", CancellationToken.None);

        // act
        var result = await service.SuspendAsync("acme", "billing overdue", "u-99", CancellationToken.None);

        // assert
        result.Should().BeOfType<TenantLifecycleResult.Success>();
        db.ChangeTracker.Clear();
        var t = await db.Tenants.SingleAsync();
        t.Status.Should().Be(TenantStatus.Suspended);
        t.SuspendedAt.Should().NotBeNull();
        t.SuspensionReason.Should().Be("billing overdue");
    }

    [Fact]
    public async Task SuspendAsync_AlreadySuspended_ReturnsInvalidStateTransition()
    {
        // arrange
        var (service, _) = BuildService();
        await service.CreateAsync("acme", "Acme", "u-1", CancellationToken.None);
        await service.SuspendAsync("acme", "reason", "u-99", CancellationToken.None);

        // act
        var result = await service.SuspendAsync("acme", "new reason", "u-99", CancellationToken.None);

        // assert
        result.Should().BeOfType<TenantLifecycleResult.InvalidStateTransition>();
    }

    [Fact]
    public async Task SuspendAsync_UnknownName_ReturnsNotFound()
    {
        // arrange
        var (service, _) = BuildService();

        // act
        var result = await service.SuspendAsync("unknown", "reason", "u-99", CancellationToken.None);

        // assert
        result.Should().BeOfType<TenantLifecycleResult.NotFound>();
    }

    [Fact]
    public async Task UnsuspendAsync_RestoresActive_AndClearsSuspensionFields()
    {
        // arrange
        var (service, db) = BuildService();
        await service.CreateAsync("acme", "Acme", "u-1", CancellationToken.None);
        await service.SuspendAsync("acme", "reason", "u-99", CancellationToken.None);

        // act
        var result = await service.UnsuspendAsync("acme", "u-99", CancellationToken.None);

        // assert
        result.Should().BeOfType<TenantLifecycleResult.Success>();
        db.ChangeTracker.Clear();
        var t = await db.Tenants.SingleAsync();
        t.Status.Should().Be(TenantStatus.Active);
        t.SuspendedAt.Should().BeNull();
        t.SuspensionReason.Should().BeNull();
    }

    [Fact]
    public async Task UnsuspendAsync_ActiveTenant_ReturnsInvalidStateTransition()
    {
        // arrange
        var (service, _) = BuildService();
        await service.CreateAsync("acme", "Acme", "u-1", CancellationToken.None);

        // act — never suspended, so unsuspending makes no sense.
        var result = await service.UnsuspendAsync("acme", "u-99", CancellationToken.None);

        // assert
        result.Should().BeOfType<TenantLifecycleResult.InvalidStateTransition>();
    }

    [Fact]
    public async Task SoftDeleteAsync_TransitionsToPendingDeletion_AndStampsTimestamp()
    {
        // arrange
        var (service, db) = BuildService();
        await service.CreateAsync("acme", "Acme", "u-1", CancellationToken.None);

        // act
        var result = await service.SoftDeleteAsync("acme", "u-99", CancellationToken.None);

        // assert
        result.Should().BeOfType<TenantLifecycleResult.Success>();
        db.ChangeTracker.Clear();
        var t = await db.Tenants.SingleAsync();
        t.Status.Should().Be(TenantStatus.PendingDeletion);
        t.PendingDeletionAt.Should().NotBeNull();
    }

    [Fact]
    public async Task SoftDeleteAsync_AlreadyPending_ReturnsInvalidStateTransition()
    {
        // arrange
        var (service, _) = BuildService();
        await service.CreateAsync("acme", "Acme", "u-1", CancellationToken.None);
        await service.SoftDeleteAsync("acme", "u-99", CancellationToken.None);

        // act
        var result = await service.SoftDeleteAsync("acme", "u-99", CancellationToken.None);

        // assert
        result.Should().BeOfType<TenantLifecycleResult.InvalidStateTransition>();
    }

    [Fact]
    public async Task ForceDeleteAsync_RightConfirmation_HardDeletes()
    {
        // arrange
        var (service, db) = BuildService();
        await service.CreateAsync("acme", "Acme", "u-1", CancellationToken.None);

        // act
        var result = await service.ForceDeleteAsync("acme", "acme", "u-99", CancellationToken.None);

        // assert
        result.Should().BeOfType<TenantLifecycleResult.Success>();
        db.ChangeTracker.Clear();
        (await db.Tenants.CountAsync()).Should().Be(0, because: "force-delete is hard, not soft.");
    }

    [Fact]
    public async Task ForceDeleteAsync_WrongConfirmation_ReturnsMismatch_AndDoesNotDelete()
    {
        // arrange
        var (service, db) = BuildService();
        await service.CreateAsync("acme", "Acme", "u-1", CancellationToken.None);

        // act
        var result = await service.ForceDeleteAsync("acme", "acmee", "u-99", CancellationToken.None);

        // assert
        result.Should().BeOfType<TenantLifecycleResult.ConfirmationMismatch>();
        db.ChangeTracker.Clear();
        (await db.Tenants.CountAsync()).Should().Be(1, because: "the tenant must remain when confirmation fails.");
    }

    [Fact]
    public async Task ForceDeleteAsync_ConfirmationIsCaseSensitive()
    {
        // arrange — name is canonically lowercase; confirm must match exactly.
        var (service, _) = BuildService();
        await service.CreateAsync("acme", "Acme", "u-1", CancellationToken.None);

        // act
        var result = await service.ForceDeleteAsync("acme", "ACME", "u-99", CancellationToken.None);

        // assert
        result.Should().BeOfType<TenantLifecycleResult.ConfirmationMismatch>(
            because: "case mismatch is intentional friction — the name is canonically lowercase.");
    }

    [Fact]
    public async Task ListAsync_ReturnsAllTenants_OrderedByName()
    {
        // arrange
        var (service, _) = BuildService();
        await service.CreateAsync("globex", "Globex", "u-1", CancellationToken.None);
        await service.CreateAsync("acme", "Acme", "u-1", CancellationToken.None);
        await service.CreateAsync("contoso", "Contoso", "u-1", CancellationToken.None);

        // act
        var tenants = await service.ListAsync(CancellationToken.None);

        // assert — the list endpoint sorts alphabetically by name.
        tenants.Select(t => t.Name).Should().Equal(new[] { "acme", "contoso", "globex" });
    }

    [Fact]
    public async Task GetByNameAsync_KnownTenant_ReturnsDetail()
    {
        // arrange
        var (service, _) = BuildService();
        await service.CreateAsync("acme", "Acme Corp", "u-1", CancellationToken.None);

        // act
        var detail = await service.GetByNameAsync("acme", CancellationToken.None);

        // assert
        detail.Should().NotBeNull();
        detail!.Name.Should().Be("acme");
        detail.DisplayName.Should().Be("Acme Corp");
        detail.Status.Should().Be(nameof(TenantStatus.Active));
        detail.ActiveMembershipCount.Should().Be(0, because: "no users have been added to the tenant yet.");
    }

    [Fact]
    public async Task GetByNameAsync_UnknownName_ReturnsNull()
    {
        // arrange
        var (service, _) = BuildService();

        // act
        var detail = await service.GetByNameAsync("missing", CancellationToken.None);

        // assert
        detail.Should().BeNull();
    }

    [Fact]
    public async Task GetByNameAsync_CountsActiveMemberships_IgnoresRemoved()
    {
        // arrange — two different users, one still active, one previously removed.
        // The (UserId, TenantId) unique index means a single user can't hold two
        // membership rows in the same tenant; this is the right shape to count.
        var (service, db) = BuildService();
        await service.CreateAsync("acme", "Acme", "u-1", CancellationToken.None);
        var tenant = await db.Tenants.SingleAsync();
        db.Users.AddRange(
            new User { Id = "u-100", UserName = "alice", Email = "alice@example.com" },
            new User { Id = "u-200", UserName = "bob", Email = "bob@example.com" });
        db.UserTenantMemberships.AddRange(
            new UserTenantMembership { Id = "m1", UserId = "u-100", TenantId = tenant.Id, RemovedAt = null },
            new UserTenantMembership { Id = "m2", UserId = "u-200", TenantId = tenant.Id, RemovedAt = DateTimeOffset.UtcNow });
        await db.SaveChangesAsync();

        // act
        var detail = await service.GetByNameAsync("acme", CancellationToken.None);

        // assert
        detail!.ActiveMembershipCount.Should().Be(1,
            because: "the count excludes memberships where RemovedAt is non-null.");
    }

    private (TenantService service, DatabaseContext db) BuildService()
    {
        var connection = new SqliteConnection("DataSource=:memory:");
        connection.Open();
        _connections.Add(connection);

        var options = new DbContextOptionsBuilder<DatabaseContext>().UseSqlite(connection).Options;
        var db = new TestDatabaseContext(options);
        db.Database.EnsureCreated();
        _contexts.Add(db);

        var service = new TenantService(
            db,
            new TenantNameValidator(),
            NullLogger<TenantService>.Instance);

        return (service, db);
    }
}
