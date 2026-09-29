using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Identity.Api.Data.Migrations
{
    /// <inheritdoc />
    public partial class LedgerAdminScope : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.InsertData(
                table: "scopes",
                columns: new[] { "id", "description", "name" },
                values: new object[] { new Guid("00000000-0000-0000-0000-000000000007"), "Act on every ledger account, not only your own", "ledger:admin" });

            migrationBuilder.InsertData(
                table: "role_scopes",
                columns: new[] { "role_id", "scope_id" },
                values: new object[] { new Guid("00000000-0000-0000-0000-000000000101"), new Guid("00000000-0000-0000-0000-000000000007") });
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DeleteData(
                table: "role_scopes",
                keyColumns: new[] { "role_id", "scope_id" },
                keyValues: new object[] { new Guid("00000000-0000-0000-0000-000000000101"), new Guid("00000000-0000-0000-0000-000000000007") });

            migrationBuilder.DeleteData(
                table: "scopes",
                keyColumn: "id",
                keyValue: new Guid("00000000-0000-0000-0000-000000000007"));
        }
    }
}
