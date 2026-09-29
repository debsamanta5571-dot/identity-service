using Identity.Api.Data;
using Identity.Api.Domain;
using Identity.Api.Security;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using OpenIddict.Abstractions;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace Identity.Api.Startup;

public sealed class BootstrapOptions
{
    public string? AdminEmail { get; set; }
    public string? AdminPassword { get; set; }
}

/// <summary>
/// Applies migrations, then creates the first admin from environment configuration, only when no users exist.
/// There is no default password anywhere in the repo.
/// </summary>
public sealed class DbInitializer(
    IServiceScopeFactory scopes, IConfiguration config, IOptions<BootstrapOptions> bootstrap, ILogger<DbInitializer> log) : IHostedService
{
    public async Task StartAsync(CancellationToken ct)
    {
        if (!config.GetValue("Database:InitializeOnStart", true)) return; // e.g. tooling, or tests that never touch the DB

        using var scope = scopes.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<IdentityDbContext>();

        await db.Database.MigrateAsync(ct);

        await SeedClientsAsync(scope.ServiceProvider.GetRequiredService<IOpenIddictApplicationManager>(), ct);

        var o = bootstrap.Value;
        if (string.IsNullOrWhiteSpace(o.AdminEmail) || string.IsNullOrEmpty(o.AdminPassword)) return;
        if (await db.Users.AnyAsync(ct)) return;

        var email = Validation.NormalizeEmail(o.AdminEmail);
        var passwordError = Validation.PasswordError(o.AdminPassword);
        if (!Validation.IsValidEmail(email) || passwordError is not null)
            throw new InvalidOperationException($"Bootstrap admin configuration is invalid. {passwordError}");

        var hasher = scope.ServiceProvider.GetRequiredService<PasswordHasher>();
        var clock = scope.ServiceProvider.GetRequiredService<TimeProvider>();
        var now = clock.GetUtcNow();
        var admin = await db.Roles.SingleAsync(r => r.Name == "admin", ct);

        var user = new User { Email = email, DisplayName = "Administrator", PasswordHash = hasher.Hash(o.AdminPassword), CreatedAt = now, UpdatedAt = now };
        user.UserRoles.Add(new UserRole { RoleId = admin.Id });
        db.Users.Add(user);
        await db.SaveChangesAsync(ct);
        log.LogInformation("Bootstrapped admin user {Email}", email);
    }

    /// <summary>
    /// OAuth clients come from configuration (section "OAuthClients"), so redirect URIs differ per environment
    /// without code changes. All clients are public (browser apps): they authenticate with PKCE, not a secret.
    /// </summary>
    private async Task SeedClientsAsync(IOpenIddictApplicationManager apps, CancellationToken ct)
    {
        foreach (var c in config.GetSection("OAuthClients").GetChildren())
        {
            var clientId = c["ClientId"] ?? throw new InvalidOperationException("OAuthClients:*:ClientId is missing.");
            var descriptor = new OpenIddictApplicationDescriptor
            {
                ClientId = clientId,
                DisplayName = c["DisplayName"] ?? clientId,
                ClientType = ClientTypes.Public,
                ConsentType = ConsentTypes.Implicit, // first-party clients: no consent screen
                Permissions =
                {
                    Permissions.Endpoints.Authorization, Permissions.Endpoints.Token, Permissions.Endpoints.Revocation,
                    Permissions.GrantTypes.AuthorizationCode, Permissions.GrantTypes.RefreshToken,
                    Permissions.ResponseTypes.Code,
                },
                Requirements = { Requirements.Features.ProofKeyForCodeExchange },
            };
            foreach (var s in Security.OAuthPrincipal.StandardScopes.Concat(SeedData.Scopes.Select(x => x.Name)))
                descriptor.Permissions.Add(Permissions.Prefixes.Scope + s);
            foreach (var uri in c.GetSection("RedirectUris").Get<string[]>() ?? [])
                descriptor.RedirectUris.Add(new Uri(uri));

            var existing = await apps.FindByClientIdAsync(clientId, ct);
            if (existing is null) await apps.CreateAsync(descriptor, ct);
            else await apps.UpdateAsync(existing, descriptor, ct);
        }
    }

    public Task StopAsync(CancellationToken ct) => Task.CompletedTask;
}
