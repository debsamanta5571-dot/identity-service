using Identity.Api.Data;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;

namespace Identity.Api.Security;

public sealed class LockoutOptions
{
    public int Threshold { get; set; } = 5;      // failures before the first lock
    public int BaseSeconds { get; set; } = 30;   // first lock duration
    public int MaxSeconds { get; set; } = 3600;  // cap
}

public sealed record AuthenticatedUser(Guid UserId, string Email, string[] Roles, string[] Scopes);

public enum LoginStatus { Success, Failed, MfaRequired }

/// <summary>Reason is for the audit log only; callers must never show it to the client.</summary>
public sealed record LoginResult(LoginStatus Status, AuthenticatedUser? User = null, string? Reason = null, Guid? UserId = null, MfaMethod? Mfa = null);

public sealed class AuthService(
    IdentityDbContext db, PasswordHasher hasher, MfaService mfa, TimeProvider clock, IOptions<LockoutOptions> lockout)
{
    private const int MaxConcurrencyRetries = 8;

    /// <summary>
    /// Password, then (if enabled) the second factor. Every failure is indistinguishable to the caller
    /// (no user enumeration) and counts toward lockout: a wrong TOTP code is a failed login too, otherwise
    /// someone holding the password could guess 6-digit codes forever.
    /// </summary>
    public async Task<LoginResult> LoginAsync(string email, string password, string? code, CancellationToken ct)
    {
        var user = await db.Users.SingleOrDefaultAsync(u => u.Email == email, ct);

        // Always burn one Argon2 verification, even for unknown users, so timing doesn't leak existence.
        var passwordOk = hasher.Verify(password, user?.PasswordHash ?? hasher.DummyHash);
        if (user is null) return new(LoginStatus.Failed, Reason: "unknown_user");
        if (!user.IsActive) return new(LoginStatus.Failed, Reason: "inactive", UserId: user.Id);

        // While locked, attempts (even correct ones) are rejected and NOT counted, so an attacker
        // can't extend someone's lock indefinitely by hammering it. Codes are not consumed either.
        if (user.LockedUntil > clock.GetUtcNow()) return new(LoginStatus.Failed, Reason: "locked", UserId: user.Id);

        var secondFactorOk = true;
        MfaMethod? usedMfa = null;
        if (passwordOk && user.MfaEnabled)
        {
            // Password was right but no code yet: ask for it. Nothing is counted or reset at this step.
            if (string.IsNullOrWhiteSpace(code)) return new(LoginStatus.MfaRequired, UserId: user.Id);
            usedMfa = await mfa.VerifyLoginCodeAsync(user, code, ct);
            secondFactorOk = usedMfa is not null;
        }
        var success = passwordOk && secondFactorOk;
        var failureReason = !passwordOk ? "bad_password" : "bad_mfa_code";

        for (var attempt = 0; attempt < MaxConcurrencyRetries; attempt++)
        {
            var now = clock.GetUtcNow();
            if (user.LockedUntil > now) return new(LoginStatus.Failed, Reason: "locked", UserId: user.Id);

            if (success)
            {
                if (user.FailedLoginCount == 0 && user.LockedUntil is null)
                    return new(LoginStatus.Success, await LoadAsync(user.Id, user.Email, ct), UserId: user.Id, Mfa: usedMfa);
                user.FailedLoginCount = 0;
                user.LockedUntil = null;
            }
            else
            {
                user.FailedLoginCount++;
                var o = lockout.Value;
                if (user.FailedLoginCount >= o.Threshold)
                {
                    var seconds = Math.Min(o.BaseSeconds * Math.Pow(2, user.FailedLoginCount - o.Threshold), o.MaxSeconds);
                    user.LockedUntil = now.AddSeconds(seconds);
                }
            }
            user.UpdatedAt = now;

            try
            {
                await db.SaveChangesAsync(ct);
                return success
                    ? new(LoginStatus.Success, await LoadAsync(user.Id, user.Email, ct), UserId: user.Id, Mfa: usedMfa)
                    : new(LoginStatus.Failed, Reason: failureReason, UserId: user.Id);
            }
            catch (DbUpdateConcurrencyException)
            {
                // another request changed this row (a parallel guess, or the MFA step being consumed);
                // reload and re-apply on the fresh values
                db.ChangeTracker.Clear();
                user = await db.Users.SingleOrDefaultAsync(u => u.Email == email, ct);
                if (user is null || !user.IsActive) return new(LoginStatus.Failed, Reason: "inactive");
            }
        }
        return new(LoginStatus.Failed, Reason: "contention"); // fail closed if we could never write
    }

    public async Task<AuthenticatedUser> LoadAsync(Guid id, string email, CancellationToken ct)
    {
        var roles = await db.UserRoles.AsNoTracking().Where(ur => ur.UserId == id)
            .Select(ur => ur.Role.Name).OrderBy(n => n).ToArrayAsync(ct);
        var scopes = await db.UserRoles.AsNoTracking().Where(ur => ur.UserId == id)
            .SelectMany(ur => ur.Role.RoleScopes).Select(rs => rs.Scope.Name).Distinct().OrderBy(n => n).ToArrayAsync(ct);
        return new AuthenticatedUser(id, email, roles, scopes);
    }
}
