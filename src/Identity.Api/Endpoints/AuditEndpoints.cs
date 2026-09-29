using System.Text.Json;
using Identity.Api.Data;
using Identity.Api.Security;
using Microsoft.EntityFrameworkCore;

namespace Identity.Api.Endpoints;

public sealed record AuditEventDto(
    long Id, DateTimeOffset OccurredAt, string EventType, bool Success, Guid? UserId, Guid? ActorId,
    string? ClientId, string? IpAddress, string? UserAgent, JsonElement? Details);

public sealed record Paged<T>(IReadOnlyList<T> Items, int Page, int PageSize, int Total);

/// <summary>Read-only. There is deliberately no PUT, PATCH or DELETE for the audit log, in the API or the database.</summary>
public static class AuditEndpoints
{
    public static void MapAuditEndpoints(this IEndpointRouteBuilder app)
    {
        app.MapGet("/api/audit", async (
            IdentityDbContext db, CancellationToken ct,
            string? eventType, bool? success, Guid? userId, Guid? actorId, string? ip,
            DateTimeOffset? from, DateTimeOffset? to, int page = 1, int pageSize = 25) =>
        {
            var errors = new Dictionary<string, string[]>();
            if (page < 1) errors["page"] = ["page must be 1 or greater."];
            if (pageSize is < 1 or > 100) errors["pageSize"] = ["pageSize must be between 1 and 100."];
            if (from > to) errors["from"] = ["from must not be after to."];
            if (errors.Count > 0) return Results.ValidationProblem(errors);

            var q = db.AuditLog.AsNoTracking().AsQueryable();
            if (!string.IsNullOrEmpty(eventType))
                q = eventType.EndsWith('*')
                    ? q.Where(e => e.EventType.StartsWith(eventType.Substring(0, eventType.Length - 1))) // "login.*"
                    : q.Where(e => e.EventType == eventType);
            if (success is not null) q = q.Where(e => e.Success == success);
            if (userId is not null) q = q.Where(e => e.UserId == userId);
            if (actorId is not null) q = q.Where(e => e.ActorId == actorId);
            if (!string.IsNullOrEmpty(ip)) q = q.Where(e => e.IpAddress == ip);
            if (from is not null) q = q.Where(e => e.OccurredAt >= from);
            if (to is not null) q = q.Where(e => e.OccurredAt <= to);

            var total = await q.CountAsync(ct);
            var rows = await q.OrderByDescending(e => e.OccurredAt).ThenByDescending(e => e.Id)
                .Skip((page - 1) * pageSize).Take(pageSize).ToListAsync(ct);

            var items = rows.Select(e => new AuditEventDto(
                e.Id, e.OccurredAt, e.EventType, e.Success, e.UserId, e.ActorId, e.ClientId, e.IpAddress, e.UserAgent,
                e.Details is null ? null : JsonDocument.Parse(e.Details).RootElement.Clone())).ToList();
            return Results.Ok(new Paged<AuditEventDto>(items, page, pageSize, total));
        }).RequireScope("audit:read");
    }
}
