using System.Security.Claims;
using Identity.Api.Data;
using Identity.Api.Domain;
using Identity.Api.Security;
using Microsoft.EntityFrameworkCore;
using Npgsql;
using OpenIddict.Abstractions;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace Identity.Api.Endpoints;

public static class UserEndpoints
{
    public static void MapUserEndpoints(this IEndpointRouteBuilder app)
    {
        var g = app.MapGroup("/api/users").RequireScope("users:admin");

        g.MapGet("/", async (IdentityDbContext db, CancellationToken ct, string? search, int page = 1, int pageSize = 25) =>
        {
            if (page < 1 || pageSize is < 1 or > 100)
                return Results.ValidationProblem(new Dictionary<string, string[]> { ["paging"] = ["page >= 1 and 1 <= pageSize <= 100."] });

            var q = db.Users.AsNoTracking().AsQueryable();
            if (!string.IsNullOrWhiteSpace(search))
            {
                var like = "%" + search.Trim().Replace("\\", "\\\\").Replace("%", "\\%").Replace("_", "\\_") + "%";
                q = q.Where(u => EF.Functions.ILike(u.Email, like) || EF.Functions.ILike(u.DisplayName, like));
            }
            var total = await q.CountAsync(ct);
            var users = await q.OrderBy(u => u.Email).Skip((page - 1) * pageSize).Take(pageSize)
                .Include(u => u.UserRoles).ThenInclude(ur => ur.Role).ToListAsync(ct);
            return Results.Ok(new Paged<UserDto>([.. users.Select(u => ToDto(u, u.UserRoles.Select(r => r.Role.Name)))], page, pageSize, total));
        });

        g.MapPost("/", async (CreateUserRequest req, ClaimsPrincipal me, IdentityDbContext db, PasswordHasher hasher, TimeProvider clock, AuditService audit, CancellationToken ct) =>
        {
            var errors = new Dictionary<string, string[]>();
            var email = Validation.NormalizeEmail(req.Email ?? "");
            if (!Validation.IsValidEmail(email)) errors["email"] = ["A valid email address is required."];
            if (Validation.PasswordError(req.Password ?? "") is { } pwError) errors["password"] = [pwError];
            var displayName = (req.DisplayName ?? "").Trim();
            if (displayName.Length is 0 or > 100) errors["displayName"] = ["Display name is required (max 100 characters)."];

            var roleNames = (req.Roles ?? []).Distinct().ToArray();
            var roles = await db.Roles.Where(r => roleNames.Contains(r.Name)).ToListAsync(ct);
            if (roles.Count != roleNames.Length)
                errors["roles"] = [$"Unknown role(s): {string.Join(", ", roleNames.Except(roles.Select(r => r.Name)))}"];

            if (errors.Count > 0) return Results.ValidationProblem(errors);
            if (await db.Users.AnyAsync(u => u.Email == email, ct)) return Conflict("A user with this email already exists.");

            var now = clock.GetUtcNow();
            var user = new User
            {
                Email = email,
                DisplayName = displayName,
                PasswordHash = hasher.Hash(req.Password!),
                CreatedAt = now,
                UpdatedAt = now,
            };
            foreach (var role in roles) user.UserRoles.Add(new UserRole { RoleId = role.Id });
            db.Users.Add(user);

            try { await db.SaveChangesAsync(ct); }
            catch (DbUpdateException e) when (e.InnerException is PostgresException { SqlState: PostgresErrorCodes.UniqueViolation })
            {
                return Conflict("A user with this email already exists."); // lost a race with a concurrent create
            }

            await audit.RecordAsync(AuditEvents.UserCreated, true, userId: user.Id, actorId: Actor(me),
                details: new { email, roles = roles.Select(r => r.Name) }, ct: ct);
            return Results.Created($"/api/users/{user.Id}", ToDto(user, roles.Select(r => r.Name)));
        });

        g.MapGet("/{id:guid}", async (Guid id, IdentityDbContext db, CancellationToken ct) =>
        {
            var user = await db.Users.AsNoTracking().Include(u => u.UserRoles).ThenInclude(ur => ur.Role)
                .SingleOrDefaultAsync(u => u.Id == id, ct);
            return user is null ? Results.Problem(statusCode: 404, title: "User not found") : Results.Ok(ToDto(user, user.UserRoles.Select(ur => ur.Role.Name)));
        });

        g.MapPut("/{id:guid}/roles", async (Guid id, SetRolesRequest req, ClaimsPrincipal me, IdentityDbContext db, TimeProvider clock, AuditService audit, CancellationToken ct) =>
        {
            var user = await db.Users.Include(u => u.UserRoles).ThenInclude(ur => ur.Role).SingleOrDefaultAsync(u => u.Id == id, ct);
            if (user is null) return Results.Problem(statusCode: 404, title: "User not found");

            var names = (req.Roles ?? []).Distinct().ToArray();
            var roles = await db.Roles.Where(r => names.Contains(r.Name)).ToListAsync(ct);
            if (roles.Count != names.Length)
                return Results.ValidationProblem(new Dictionary<string, string[]>
                {
                    ["roles"] = [$"Unknown role(s): {string.Join(", ", names.Except(roles.Select(r => r.Name)))}"],
                });

            var before = user.UserRoles.Select(ur => ur.Role.Name).Order().ToArray();
            user.UserRoles.Clear();
            foreach (var role in roles) user.UserRoles.Add(new UserRole { UserId = user.Id, RoleId = role.Id });
            user.UpdatedAt = clock.GetUtcNow();
            await db.SaveChangesAsync(ct);

            await audit.RecordAsync(AuditEvents.RoleChanged, true, userId: user.Id, actorId: Actor(me),
                details: new { before, after = roles.Select(r => r.Name).Order() }, ct: ct);
            return Results.Ok(ToDto(user, roles.Select(r => r.Name)));
        });

        g.MapPut("/{id:guid}/status", async (
            Guid id, SetStatusRequest req, ClaimsPrincipal me, IdentityDbContext db, TimeProvider clock, AuditService audit,
            IOpenIddictAuthorizationManager authorizations, IOpenIddictTokenManager tokens, CancellationToken ct) =>
        {
            var user = await db.Users.Include(u => u.UserRoles).ThenInclude(ur => ur.Role).SingleOrDefaultAsync(u => u.Id == id, ct);
            if (user is null) return Results.Problem(statusCode: 404, title: "User not found");
            if (req.IsActive is null) return Results.ValidationProblem(new Dictionary<string, string[]> { ["isActive"] = ["isActive is required."] });
            if (!req.IsActive.Value && Actor(me) == id)
                return Results.Problem(statusCode: 400, title: "Not allowed", detail: "You cannot deactivate your own account.");

            user.IsActive = req.IsActive.Value;
            user.UpdatedAt = clock.GetUtcNow();
            await db.SaveChangesAsync(ct);

            if (!user.IsActive) // a deactivated user loses every session immediately
            {
                await tokens.RevokeBySubjectAsync(id.ToString(), ct);
                await authorizations.RevokeBySubjectAsync(id.ToString(), ct);
            }

            await audit.RecordAsync(AuditEvents.UserStatusChanged, true, userId: id, actorId: Actor(me), details: new { isActive = user.IsActive }, ct: ct);
            return Results.Ok(ToDto(user, user.UserRoles.Select(ur => ur.Role.Name)));
        });
    }

    private static Guid? Actor(ClaimsPrincipal me) => Guid.TryParse(me.FindFirstValue(Claims.Subject), out var id) ? id : null;

    private static IResult Conflict(string detail) => Results.Problem(statusCode: 409, title: "Conflict", detail: detail);

    private static UserDto ToDto(User u, IEnumerable<string> roles) =>
        new(u.Id, u.Email, u.DisplayName, u.IsActive, roles.Order().ToArray(), u.CreatedAt, u.MfaEnabled, u.LockedUntil);
}
