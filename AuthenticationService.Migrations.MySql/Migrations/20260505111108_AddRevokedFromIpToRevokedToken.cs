using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace AuthenticationService.Migrations.MySql.Migrations
{
    /// <inheritdoc />
    public partial class AddRevokedFromIpToRevokedToken : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<string>(
                name: "RevokedFromIp",
                table: "RevokedTokens",
                type: "varchar(45)",
                maxLength: 45,
                nullable: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "RevokedFromIp",
                table: "RevokedTokens");
        }
    }
}
