using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace AuthenticationService.Migrations
{
    /// <inheritdoc />
    public partial class RenameAccessRecordsToRevokedTokenAccessAttempts : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            // Drop the now-redundant Revoked column. Every row in this table is, by virtue
            // of the only code path that writes it, a revoked-token replay attempt — so
            // Revoked was always true. Removing it lets the table name carry the meaning.
            migrationBuilder.DropColumn(
                name: "Revoked",
                table: "AccessRecords");

            // Rename the table to reflect what it actually stores.
            migrationBuilder.RenameTable(
                name: "AccessRecords",
                newName: "RevokedTokenAccessAttempts");

            // Rename the index to follow the new table name.
            migrationBuilder.RenameIndex(
                name: "IX_AccessRecords_TokenJti",
                newName: "IX_RevokedTokenAccessAttempts_TokenJti",
                table: "RevokedTokenAccessAttempts");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.RenameIndex(
                name: "IX_RevokedTokenAccessAttempts_TokenJti",
                newName: "IX_AccessRecords_TokenJti",
                table: "RevokedTokenAccessAttempts");

            migrationBuilder.RenameTable(
                name: "RevokedTokenAccessAttempts",
                newName: "AccessRecords");

            migrationBuilder.AddColumn<bool>(
                name: "Revoked",
                table: "AccessRecords",
                type: "tinyint(1)",
                nullable: false,
                defaultValue: false);
        }
    }
}
