using System.Security.Claims;
using System.Text.RegularExpressions;
using OpenIddict.Abstractions;
using Identity.Api.Data;
using Identity.Api.Domain;
using Identity.Api.Security;
using Microsoft.EntityFrameworkCore;
using Npgsql;

namespace Identity.Api.Endpoints;

public static partial class RoleEndpoints
{
    [GeneratedRegex("^[a-z][a-z0-9-]{1,49}$")]
    private static partial Regex RoleName();

    public static void MapRoleEndpoints(this IEndpointRouteBuilder app)
    {
        app.MapGet("/api/scopes", async (IdentityDbContext db, CancellationToken ct) =>
            await db.Scopes.AsNoTracking().OrderBy(s => s.Name).Select(s => new ScopeDto(s.Name, s.Description)).ToListAsync(ct))
            .RequireScope("users:admin");

        var g = app.MapGroup("/api/roles").RequireScope("users:admin");

        g.MapGet("/", async (IdentityDbContext db, CancellationToken ct) =>
        {
            var roles = await db.Roles.AsNoTracking().Include(r => r.RoleScopes).ThenInclude(rs => rs.Scope)
                .OrderBy(r => r.Name).ToListAsync(ct);
            return roles.Select(ToDto);
        });

        g.MapPost("/", async (CreateRoleRequest req, ClaimsPrincipal me, IdentityDbContext db, AuditService audit, CancellationToken ct) =>
        {
            var errors = new Dictionary<string, string[]>();
            var name = req.Name ?? "";
            if (!RoleName().IsMatch(name)) errors["name"] = ["Name must be 2-50 chars: lowercase letters, digits, hyphens, starting with a letter."];

            var scopeNames = (req.Scopes ?? []).Distinct().ToArray();
            var scopes = await db.Scopes.Where(s => scopeNames.Contains(s.Name)).ToListAsync(ct);
            if (scopes.Count != scopeNames.Length)
                errors["scopes"] = [$"Unknown scope(s): {string.Join(", ", scopeNames.Except(scopes.Select(s => s.Name)))}"];

            if (errors.Count > 0) return Results.ValidationProblem(errors);
            if (await db.Roles.AnyAsync(r => r.Name == name, ct)) return Results.Problem(statusCode: 409, title: "Conflict", detail: "A role with this name already exists.");

            var role = new Role { Name = name, Description = (req.Description ?? "").Trim() };
            foreach (var s in scopes) role.RoleScopes.Add(new RoleScope { ScopeId = s.Id, Scope = s });
            db.Roles.Add(role);
            try { await db.SaveChangesAsync(ct); }
            catch (DbUpdateException e) when (e.InnerException is PostgresException { SqlState: PostgresErrorCodes.UniqueViolation })
            {
                return Results.Problem(statusCode: 409, title: "Conflict", detail: "A role with this name already exists.");
            }
            Guid? actor = Guid.TryParse(me.FindFirstValue(OpenIddictConstants.Claims.Subject), out var a) ? a : null;
            await audit.RecordAsync(AuditEvents.RoleCreated, true, actorId: actor, details: new { name, scopes = scopes.Select(x => x.Name) }, ct: ct);
            return Results.Created($"/api/roles/{role.Id}", ToDto(role));
        });
    }

    private static RoleDto ToDto(Role r) =>
        new(r.Id, r.Name, r.Description, r.RoleScopes.Select(rs => rs.Scope.Name).Order().ToArray());
}
