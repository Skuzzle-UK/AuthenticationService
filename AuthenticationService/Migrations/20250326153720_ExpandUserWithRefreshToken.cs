using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace AuthenticationService.Migrations
{
    /// <inheritdoc />
    public partial class ExpandUserWithRefreshToken : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<string>(
                name: "RefreshToken",
                table: "AspNetUsers",
                type: "longtext",
                nullable: true);

            migrationBuilder.AddColumn<DateTime>(
                name: "RefreshTokenExipiresAt",
                table: "AspNetUsers",
                type: "datetime(6)",
                nullable: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "RefreshToken",
                table: "AspNetUsers");

            migrationBuilder.DropColumn(
                name: "RefreshTokenExipiresAt",
                table: "AspNetUsers");
        }
    }
}
