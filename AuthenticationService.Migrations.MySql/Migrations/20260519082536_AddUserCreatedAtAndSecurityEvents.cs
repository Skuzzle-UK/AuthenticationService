using System;
using Microsoft.EntityFrameworkCore.Migrations;
using MySql.EntityFrameworkCore.Metadata;

#nullable disable

namespace AuthenticationService.Migrations.MySql.Migrations
{
    /// <inheritdoc />
    public partial class AddUserCreatedAtAndSecurityEvents : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AlterColumn<DateTime>(
                name: "DateOfBirth",
                table: "AspNetUsers",
                type: "datetime(6)",
                nullable: true,
                oldClrType: typeof(DateOnly),
                oldType: "date",
                oldNullable: true);

            // Backfill default for existing rows when this column is first added — MySQL
            // requires the function call wrapped in parens to be accepted as a DEFAULT
            // expression (bare `DEFAULT UTC_TIMESTAMP(6)` is a syntax error). After this
            // migration the column technically retains the DEFAULT, but EF's INSERTs
            // always carry the C# value from User.CreatedAt's initializer so the default
            // only fires during this very migration. Hand-edited from EF's auto-generated
            // `defaultValue: DateTime.MinValue` because the model deliberately doesn't
            // configure a default (which would force provider-specific SQL into the
            // production model — see DatabaseContext.OnModelCreating comment).
            migrationBuilder.AddColumn<DateTime>(
                name: "CreatedAt",
                table: "AspNetUsers",
                type: "datetime(6)",
                nullable: false,
                defaultValueSql: "(UTC_TIMESTAMP(6))");

            migrationBuilder.CreateTable(
                name: "SecurityEvents",
                columns: table => new
                {
                    Id = table.Column<long>(type: "bigint", nullable: false)
                        .Annotation("MySQL:ValueGenerationStrategy", MySQLValueGenerationStrategy.IdentityColumn),
                    Timestamp = table.Column<DateTime>(type: "datetime(6)", nullable: false),
                    EventId = table.Column<int>(type: "int", nullable: false),
                    EventName = table.Column<string>(type: "varchar(100)", maxLength: 100, nullable: false),
                    Level = table.Column<string>(type: "varchar(20)", maxLength: 20, nullable: false),
                    Message = table.Column<string>(type: "varchar(2000)", maxLength: 2000, nullable: true),
                    UserId = table.Column<string>(type: "varchar(450)", maxLength: 450, nullable: true),
                    IpAddress = table.Column<string>(type: "varchar(45)", maxLength: 45, nullable: true),
                    PropertiesJson = table.Column<string>(type: "longtext", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_SecurityEvents", x => x.Id);
                })
                .Annotation("MySQL:Charset", "utf8mb4");

            migrationBuilder.CreateIndex(
                name: "IX_SecurityEvents_EventId",
                table: "SecurityEvents",
                column: "EventId");

            migrationBuilder.CreateIndex(
                name: "IX_SecurityEvents_UserId_Timestamp",
                table: "SecurityEvents",
                columns: new[] { "UserId", "Timestamp" });
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "SecurityEvents");

            migrationBuilder.DropColumn(
                name: "CreatedAt",
                table: "AspNetUsers");

            migrationBuilder.AlterColumn<DateOnly>(
                name: "DateOfBirth",
                table: "AspNetUsers",
                type: "date",
                nullable: true,
                oldClrType: typeof(DateTime),
                oldType: "datetime(6)",
                oldNullable: true);
        }
    }
}
