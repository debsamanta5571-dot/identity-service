using System.Text.RegularExpressions;
using Identity.Api.Domain;
using Microsoft.EntityFrameworkCore;

namespace Identity.Api.Data;

public class IdentityDbContext(DbContextOptions<IdentityDbContext> options) : DbContext(options)
{
    public DbSet<User> Users => Set<User>();
    public DbSet<Role> Roles => Set<Role>();
    public DbSet<Scope> Scopes => Set<Scope>();
    public DbSet<UserRole> UserRoles => Set<UserRole>();
    public DbSet<RoleScope> RoleScopes => Set<RoleScope>();
    public DbSet<RecoveryCode> RecoveryCodes => Set<RecoveryCode>();
    public DbSet<AuditEvent> AuditLog => Set<AuditEvent>();

    // Second line of defence after the database triggers (see the AuditLog migration): fail fast in code.
    private void GuardAuditLog()
    {
        if (ChangeTracker.Entries<AuditEvent>().Any(e => e.State is EntityState.Modified or EntityState.Deleted))
            throw new InvalidOperationException("The audit log is append-only.");
    }

    public override int SaveChanges(bool acceptAllChangesOnSuccess)
    {
        GuardAuditLog();
        return base.SaveChanges(acceptAllChangesOnSuccess);
    }

    public override Task<int> SaveChangesAsync(bool acceptAllChangesOnSuccess, CancellationToken cancellationToken = default)
    {
        GuardAuditLog();
        return base.SaveChangesAsync(acceptAllChangesOnSuccess, cancellationToken);
    }

    protected override void OnModelCreating(ModelBuilder b)
    {
        b.HasPostgresExtension("citext");
        b.UseOpenIddict<Guid>();

        b.Entity<User>(e =>
        {
            e.Property(x => x.Email).HasColumnType("citext");
            e.HasIndex(x => x.Email).IsUnique();
            e.Property(x => x.PasswordHash).HasMaxLength(255);
            e.Property(x => x.DisplayName).HasMaxLength(100);
            e.Property(x => x.Version).HasColumnName("xmin").HasColumnType("xid")
                .ValueGeneratedOnAddOrUpdate().IsConcurrencyToken();
        });

        b.Entity<AuditEvent>(e =>
        {
            e.ToTable("audit_log");
            e.Property(x => x.EventType).HasMaxLength(64);
            e.Property(x => x.ClientId).HasMaxLength(100);
            e.Property(x => x.IpAddress).HasMaxLength(45);
            e.Property(x => x.UserAgent).HasMaxLength(512);
            e.Property(x => x.Details).HasColumnType("jsonb");
            e.HasIndex(x => new { x.OccurredAt, x.Id }).IsDescending();
            e.HasIndex(x => new { x.UserId, x.OccurredAt });
            e.HasIndex(x => new { x.EventType, x.OccurredAt });
        });

        b.Entity<RecoveryCode>(e =>
        {
            e.Property(x => x.CodeHash).HasMaxLength(64);
            e.HasIndex(x => new { x.UserId, x.CodeHash }).IsUnique();
            e.HasOne<User>().WithMany(u => u.RecoveryCodes).HasForeignKey(x => x.UserId).OnDelete(DeleteBehavior.Cascade);
        });

        b.Entity<Role>(e =>
        {
            e.Property(x => x.Name).HasMaxLength(50);
            e.Property(x => x.Description).HasMaxLength(200);
            e.HasIndex(x => x.Name).IsUnique();
            e.HasData(SeedData.Roles);
        });

        b.Entity<Scope>(e =>
        {
            e.Property(x => x.Name).HasMaxLength(50);
            e.Property(x => x.Description).HasMaxLength(200);
            e.HasIndex(x => x.Name).IsUnique();
            e.HasData(SeedData.Scopes);
        });

        b.Entity<UserRole>(e =>
        {
            e.HasKey(x => new { x.UserId, x.RoleId });
            e.HasOne(x => x.User).WithMany(u => u.UserRoles).HasForeignKey(x => x.UserId).OnDelete(DeleteBehavior.Cascade);
            e.HasOne(x => x.Role).WithMany(r => r.UserRoles).HasForeignKey(x => x.RoleId).OnDelete(DeleteBehavior.Cascade);
        });

        b.Entity<RoleScope>(e =>
        {
            e.HasKey(x => new { x.RoleId, x.ScopeId });
            e.HasOne(x => x.Role).WithMany(r => r.RoleScopes).HasForeignKey(x => x.RoleId).OnDelete(DeleteBehavior.Cascade);
            e.HasOne(x => x.Scope).WithMany().HasForeignKey(x => x.ScopeId).OnDelete(DeleteBehavior.Cascade);
            e.HasData(SeedData.RoleScopes.Select(rs => new { rs.RoleId, rs.ScopeId }));
        });

        // snake_case tables and columns without pulling in another package
        foreach (var entity in b.Model.GetEntityTypes())
        {
            entity.SetTableName(Snake(entity.GetTableName()!));
            foreach (var p in entity.GetProperties())
                p.SetColumnName(Snake(p.GetColumnName()));
        }
    }

    private static string Snake(string s) => Regex.Replace(s.Replace("OpenIddict", "Openiddict"), "(?<=[a-z0-9])[A-Z]", "_$0").ToLowerInvariant();
}
