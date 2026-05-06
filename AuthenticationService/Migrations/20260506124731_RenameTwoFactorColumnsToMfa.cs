using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace AuthenticationService.Migrations
{
    /// <inheritdoc />
    public partial class RenameTwoFactorColumnsToMfa : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.RenameColumn(
                name: "WaitingForTwoFactorAuthentication",
                table: "AspNetUsers",
                newName: "WaitingForMfa");

            migrationBuilder.RenameColumn(
                name: "Preferred2FAProvider",
                table: "AspNetUsers",
                newName: "PreferredMfaProvider");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.RenameColumn(
                name: "WaitingForMfa",
                table: "AspNetUsers",
                newName: "WaitingForTwoFactorAuthentication");

            migrationBuilder.RenameColumn(
                name: "PreferredMfaProvider",
                table: "AspNetUsers",
                newName: "Preferred2FAProvider");
        }
    }
}
