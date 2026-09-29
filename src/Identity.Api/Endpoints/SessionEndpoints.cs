using System.Security.Claims;
using Identity.Api.Data;
using Identity.Api.Security;
using Microsoft.EntityFrameworkCore;
using OpenIddict.Abstractions;
using OpenIddict.EntityFrameworkCore.Models;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace Identity.Api.Endpoints;

public sealed record SessionDto(Guid Id, Guid UserId, string? Email, string? ClientId, DateTimeOffset? CreatedAt, DateTimeOffset? ExpiresAt);

/// <summary>
/// A "session" is a refresh-token family: one authorization created at login, with exactly one live refresh
/// token at a time (rotation). Revoking the authorization kills the session; access tokens already issued
/// remain valid until their short expiry (they are stateless JWTs the ledger verifies offline).
/// </summary>
public static class SessionEndpoints
{
    public static void MapSessionEndpoints(this IEndpointRouteBuilder app)
    {
        var g = app.MapGroup("/api/sessions").RequireScope("users:admin");

        g.MapGet("/", async (IdentityDbContext db, TimeProvider clock, CancellationToken ct, Guid? userId) =>
        {
            var now = clock.GetUtcNow().UtcDateTime;
            var live = await db.Set<OpenIddictEntityFrameworkCoreToken<Guid>>().AsNoTracking()
                .Where(t => t.Type == TokenTypeIdentifiers.RefreshToken && t.Status == Statuses.Valid && t.ExpirationDate > now
                            && t.Authorization != null && t.Authorization.Status == Statuses.Valid)
                .Select(t => new
                {
                    AuthorizationId = t.Authorization!.Id,
                    t.Subject,
                    ClientId = t.Application!.ClientId,
                    Created = t.Authorization.CreationDate,
                    t.ExpirationDate,
                })
                .ToListAsync(ct);

            var subjects = live.Select(x => Guid.TryParse(x.Subject, out var g) ? g : Guid.Empty).Distinct().ToList();
            var emails = await db.Users.AsNoTracking().Where(u => subjects.Contains(u.Id)).ToDictionaryAsync(u => u.Id, u => u.Email, ct);

            var sessions = live
                .Select(x => (Row: x, User: Guid.TryParse(x.Subject, out var u) ? u : Guid.Empty))
                .Where(x => userId is null || x.User == userId)
                .OrderByDescending(x => x.Row.Created)
                .Select(x => new SessionDto(x.Row.AuthorizationId, x.User, emails.GetValueOrDefault(x.User), x.Row.ClientId,
                    x.Row.Created is null ? null : new DateTimeOffset(DateTime.SpecifyKind(x.Row.Created.Value, DateTimeKind.Utc)),
                    x.Row.ExpirationDate is null ? null : new DateTimeOffset(DateTime.SpecifyKind(x.Row.ExpirationDate.Value, DateTimeKind.Utc))))
                .ToList();
            return Results.Ok(sessions);
        });

        g.MapDelete("/{id:guid}", async (
            Guid id, ClaimsPrincipal me, IOpenIddictAuthorizationManager authorizations, IOpenIddictTokenManager tokens,
            AuditService audit, CancellationToken ct) =>
        {
            var authorization = await authorizations.FindByIdAsync(id.ToString(), ct);
            if (authorization is null) return Results.Problem(statusCode: 404, title: "Session not found");

            _ = Guid.TryParse(await authorizations.GetSubjectAsync(authorization, ct), out var userId);
            await tokens.RevokeByAuthorizationIdAsync(id.ToString(), ct);
            await authorizations.TryRevokeAsync(authorization, ct);

            Guid? actor = Guid.TryParse(me.FindFirstValue(Claims.Subject), out var a) ? a : null;
            await audit.RecordAsync(AuditEvents.SessionRevoked, true, userId: userId == default ? null : userId, actorId: actor,
                details: new { authorizationId = id }, ct: ct);
            return Results.NoContent();
        });
    }
}
