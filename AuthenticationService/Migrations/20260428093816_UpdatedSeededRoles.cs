using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace AuthenticationService.Migrations
{
    /// <inheritdoc />
    public partial class UpdatedSeededRoles : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.UpdateData(
                table: "AspNetRoles",
                keyColumn: "Id",
                keyValue: "2b3ad022-d787-4e96-9a59-55b286a6e482",
                columns: new[] { "Description", "Name", "NormalizedName" },
                values: new object[] { "Default user role", "DefaultUser", "DEFAULTUSER" });

            migrationBuilder.UpdateData(
                table: "AspNetRoles",
                keyColumn: "Id",
                keyValue: "c6c93b9b-7e04-4812-8395-7b2eaad474da",
                column: "Description",
                value: "Overall admin role");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.UpdateData(
                table: "AspNetRoles",
                keyColumn: "Id",
                keyValue: "2b3ad022-d787-4e96-9a59-55b286a6e482",
                columns: new[] { "Description", "Name", "NormalizedName" },
                values: new object[] { "Regular user role", "User", "User" });

            migrationBuilder.UpdateData(
                table: "AspNetRoles",
                keyColumn: "Id",
                keyValue: "c6c93b9b-7e04-4812-8395-7b2eaad474da",
                column: "Description",
                value: "Regular admin role");
        }
    }
}
