using AuthenticationService.Storage;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Design;

namespace AuthenticationService.Migrations.MySql;

/// <summary>
/// Used by <c>dotnet ef migrations add</c> when this project is both the <c>--project</c>
/// and the <c>--startup-project</c>. EF CLI calls <see cref="CreateDbContext"/> to get
/// a <c>DatabaseContext</c> wired with the MySQL provider so it can diff the model
/// against the snapshot in this assembly. The connection string is a placeholder —
/// <c>migrations add</c> doesn't actually connect.
/// </summary>
public sealed class DesignTimeFactory : IDesignTimeDbContextFactory<DatabaseContext>
{
    public DatabaseContext CreateDbContext(string[] args)
    {
        var builder = new DbContextOptionsBuilder<DatabaseContext>();
        builder.UseMySQL(
            "server=design-time-placeholder;port=3306;database=AuthenticationService;user=root;password=placeholder;",
            mysql => mysql.MigrationsAssembly(typeof(DesignTimeFactory).Assembly.GetName().Name));
        return new DatabaseContext(builder.Options);
    }
}
