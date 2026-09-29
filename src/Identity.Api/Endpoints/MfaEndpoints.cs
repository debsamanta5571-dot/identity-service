using System.Security.Claims;
using Identity.Api.Security;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace Identity.Api.Endpoints;

public sealed record MfaCodeRequest(string? Code);

/// <summary>Self-service: a user manages only their own second factor, identified by the token's subject.</summary>
public static class MfaEndpoints
{
    public static void MapMfaEndpoints(this IEndpointRouteBuilder app)
    {
        var g = app.MapGroup("/api/mfa").RequireAuthorization().RequireRateLimiting("per-ip");

        g.MapPost("/enroll", async (ClaimsPrincipal me, MfaService mfa, AuditService audit, CancellationToken ct) =>
        {
            var enrollment = await mfa.EnrollAsync(UserId(me), ct);
            if (enrollment is not null) await audit.RecordAsync(AuditEvents.MfaEnrollmentStarted, true, userId: UserId(me), actorId: UserId(me), ct: ct);
            return enrollment is null
                ? Results.Problem(statusCode: 409, title: "Conflict", detail: "MFA is already enabled for this account.")
                : Results.Ok(enrollment);
        });

        g.MapPost("/confirm", async (MfaCodeRequest req, ClaimsPrincipal me, MfaService mfa, AuditService audit, CancellationToken ct) =>
        {
            if (string.IsNullOrWhiteSpace(req.Code)) return Invalid();
            var codes = await mfa.ConfirmEnrollmentAsync(UserId(me), req.Code, ct);
            await audit.RecordAsync(codes is null ? AuditEvents.MfaFailure : AuditEvents.MfaEnabled, codes is not null,
                userId: UserId(me), actorId: UserId(me), details: codes is null ? new { step = "confirm" } : null, ct: ct);
            return codes is null ? Invalid() : Results.Ok(new { recoveryCodes = codes });
        });

        g.MapPost("/disable", async (MfaCodeRequest req, ClaimsPrincipal me, MfaService mfa, AuditService audit, CancellationToken ct) =>
        {
            if (string.IsNullOrWhiteSpace(req.Code)) return Invalid();
            var ok = await mfa.DisableAsync(UserId(me), req.Code, ct);
            await audit.RecordAsync(ok ? AuditEvents.MfaDisabled : AuditEvents.MfaFailure, ok, userId: UserId(me), actorId: UserId(me),
                details: ok ? null : new { step = "disable" }, ct: ct);
            return ok ? Results.NoContent() : Invalid();
        });
    }

    private static Guid UserId(ClaimsPrincipal p) => Guid.Parse(p.FindFirstValue(Claims.Subject)!);

    private static IResult Invalid() =>
        Results.Problem(statusCode: 400, title: "Invalid code", detail: "The code is incorrect, expired, or MFA is not in the right state.");
}
