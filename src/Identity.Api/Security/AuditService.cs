using System.Text.Json;
using Identity.Api.Data;
using Identity.Api.Domain;

namespace Identity.Api.Security;

public static class AuditEvents
{
    public const string LoginSuccess = "login.success";
    public const string LoginFailure = "login.failure";
    public const string LoginMfaRequired = "login.mfa_required";
    public const string MfaEnrollmentStarted = "mfa.enrollment_started";
    public const string MfaEnabled = "mfa.enabled";
    public const string MfaDisabled = "mfa.disabled";
    public const string MfaFailure = "mfa.failure";
    public const string MfaRecoveryCodeUsed = "mfa.recovery_code_used";
    public const string TokenIssued = "token.issued";
    public const string TokenRevoked = "token.revoked";
    public const string RefreshReuseDetected = "token.refresh_reuse_detected";
    public const string UserCreated = "user.created";
    public const string UserStatusChanged = "user.status_changed";
    public const string RoleChanged = "role.changed";
    public const string RoleCreated = "role.created";
    public const string SessionRevoked = "session.revoked";
}

/// <summary>
/// Writes audit rows in their own scope and transaction, so an event is recorded even if the request that
/// caused it later fails or rolls back. A failure to write is not swallowed: a request whose audit
/// record cannot be stored should not silently succeed.
/// </summary>
public sealed class AuditService(IServiceScopeFactory scopes, IHttpContextAccessor http, TimeProvider clock)
{
    public async Task RecordAsync(
        string eventType, bool success, Guid? userId = null, Guid? actorId = null, string? clientId = null,
        object? details = null, CancellationToken ct = default)
    {
        var ctx = http.HttpContext;
        var ua = ctx?.Request.Headers.UserAgent.ToString();
        var entry = new AuditEvent
        {
            OccurredAt = clock.GetUtcNow(),
            EventType = eventType,
            Success = success,
            UserId = userId,
            ActorId = actorId,
            ClientId = clientId,
            IpAddress = ctx?.Connection.RemoteIpAddress?.ToString(),
            UserAgent = string.IsNullOrEmpty(ua) ? null : ua[..Math.Min(ua.Length, 512)],
            Details = details is null ? null : JsonSerializer.Serialize(details),
        };

        using var scope = scopes.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<IdentityDbContext>();
        db.AuditLog.Add(entry);
        await db.SaveChangesAsync(ct);
    }
}
