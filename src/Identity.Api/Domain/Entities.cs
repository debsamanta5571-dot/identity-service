namespace Identity.Api.Domain;

public class User
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public string Email { get; set; } = "";
    public string PasswordHash { get; set; } = "";
    public string DisplayName { get; set; } = "";
    public bool IsActive { get; set; } = true;
    public int FailedLoginCount { get; set; }
    public DateTimeOffset? LockedUntil { get; set; }
    public bool MfaEnabled { get; set; }
    public byte[]? MfaSecret { get; set; }      // AES-GCM encrypted TOTP secret (never stored in clear)
    public long? MfaLastStep { get; set; }      // last accepted TOTP time step: a code is only good once
    public DateTimeOffset CreatedAt { get; set; }
    public DateTimeOffset UpdatedAt { get; set; }

    // Postgres xmin system column: optimistic concurrency so parallel failed logins can't lose increments.
    public uint Version { get; set; }

    public List<UserRole> UserRoles { get; } = [];
    public List<RecoveryCode> RecoveryCodes { get; } = [];
}

public class RecoveryCode
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public Guid UserId { get; set; }
    public string CodeHash { get; set; } = "";  // SHA-256 (hex) of a high-entropy random code
    public DateTimeOffset? UsedAt { get; set; }
}

public class Role
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public string Name { get; set; } = "";
    public string Description { get; set; } = "";
    public List<UserRole> UserRoles { get; } = [];
    public List<RoleScope> RoleScopes { get; } = [];
}

public class Scope
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public string Name { get; set; } = "";
    public string Description { get; set; } = "";
}

public class UserRole
{
    public Guid UserId { get; set; }
    public Guid RoleId { get; set; }
    public User User { get; set; } = null!;
    public Role Role { get; set; } = null!;
}

public class RoleScope
{
    public Guid RoleId { get; set; }
    public Guid ScopeId { get; set; }
    public Role Role { get; set; } = null!;
    public Scope Scope { get; set; } = null!;
}

/// <summary>One row per security-relevant event. Append-only: enforced in the DB, not just in code.</summary>
public class AuditEvent
{
    public long Id { get; set; }
    public DateTimeOffset OccurredAt { get; set; }
    public string EventType { get; set; } = "";
    public bool Success { get; set; }
    public Guid? UserId { get; set; }      // whom the event is about
    public Guid? ActorId { get; set; }     // who did it (e.g. the admin changing a role); null for anonymous
    public string? ClientId { get; set; }
    public string? IpAddress { get; set; }
    public string? UserAgent { get; set; }
    public string? Details { get; set; }   // jsonb; never contains passwords, tokens or codes
}
