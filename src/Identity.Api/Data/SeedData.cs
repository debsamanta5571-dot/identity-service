using Identity.Api.Domain;

namespace Identity.Api.Data;

/// <summary>Fixed ids so the seed is identical in every environment and migrations stay deterministic.</summary>
public static class SeedData
{
    private static Guid G(int n) => new($"00000000-0000-0000-0000-{n:D12}");

    public static readonly Scope[] Scopes =
    [
        new() { Id = G(1), Name = "accounts:read",   Description = "Read ledger accounts and balances" },
        new() { Id = G(2), Name = "accounts:write",  Description = "Create and modify ledger accounts" },
        new() { Id = G(3), Name = "transfers:read",  Description = "Read transfers and statements" },
        new() { Id = G(4), Name = "transfers:write", Description = "Create transfers" },
        new() { Id = G(5), Name = "audit:read",      Description = "Query the audit log" },
        new() { Id = G(6), Name = "users:admin",     Description = "Manage users and roles" },
        new() { Id = G(7), Name = "ledger:admin",    Description = "Act on every ledger account, not only your own" },
    ];

    public static readonly Role[] Roles =
    [
        new() { Id = G(101), Name = "admin",    Description = "Full access including user administration" },
        new() { Id = G(102), Name = "operator", Description = "Operate the ledger: accounts and transfers" },
        new() { Id = G(103), Name = "auditor",  Description = "Read-only access including the audit log" },
    ];

    public static readonly (Guid RoleId, Guid ScopeId)[] RoleScopes =
    [
        .. Enumerable.Range(1, 7).Select(s => (G(101), G(s))), // admin: everything, including ledger:admin
        .. Enumerable.Range(1, 4).Select(s => (G(102), G(s))),
        .. new[] { 1, 3, 5 }.Select(s => (G(103), G(s))),
    ];
}
