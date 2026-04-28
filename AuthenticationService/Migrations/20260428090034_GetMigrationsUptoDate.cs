using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace AuthenticationService.Migrations
{
    /// <inheritdoc />
    public partial class GetMigrationsUptoDate : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.UpdateData(
                table: "AspNetRoles",
                keyColumn: "Id",
                keyValue: "2b3ad022-d787-4e96-9a59-55b286a6e482",
                column: "ConcurrencyStamp",
                value: "ab5a8990-8062-41ea-b0ce-395599973a36");

            migrationBuilder.UpdateData(
                table: "AspNetRoles",
                keyColumn: "Id",
                keyValue: "c6c93b9b-7e04-4812-8395-7b2eaad474da",
                column: "ConcurrencyStamp",
                value: "0971cc17-84a5-44fb-b773-1b7fd4e58c38");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.UpdateData(
                table: "AspNetRoles",
                keyColumn: "Id",
                keyValue: "2b3ad022-d787-4e96-9a59-55b286a6e482",
                column: "ConcurrencyStamp",
                value: null);

            migrationBuilder.UpdateData(
                table: "AspNetRoles",
                keyColumn: "Id",
                keyValue: "c6c93b9b-7e04-4812-8395-7b2eaad474da",
                column: "ConcurrencyStamp",
                value: null);
        }
    }
}
