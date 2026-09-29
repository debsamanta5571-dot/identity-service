using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Identity.Api.Data;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Logging;
using Npgsql;
using Testcontainers.PostgreSql;

namespace Identity.Tests.Infrastructure;

/// <summary>One real PostgreSQL container shared by all tests.</summary>
public sealed class PostgresFixture : IAsyncLifetime
{
    // TEST_PG_CONNECTION points the tests at an existing server (e.g. a CI service container) instead of starting one.
    private static readonly string? External = Environment.GetEnvironmentVariable("TEST_PG_CONNECTION");
    private readonly PostgreSqlContainer? _pg = External is null ? new PostgreSqlBuilder("postgres:16-alpine").Build() : null;

    public string ConnectionString => External ?? _pg!.GetConnectionString();

    public Task InitializeAsync() => _pg?.StartAsync() ?? Task.CompletedTask;

    public Task DisposeAsync() => _pg?.DisposeAsync().AsTask() ?? Task.CompletedTask;
}

[CollectionDefinition("db")]
public sealed class DbCollection : ICollectionFixture<PostgresFixture>;

public sealed class TestClock : TimeProvider
{
    // Real "now" (JWT validation uses the system clock too), truncated to whole seconds because PostgreSQL
    // stores microseconds and the tests compare stored timestamps for equality.
    private DateTimeOffset _now = DateTimeOffset.FromUnixTimeSeconds(DateTimeOffset.UtcNow.ToUnixTimeSeconds());
    public override DateTimeOffset GetUtcNow() => _now;
    public void Advance(TimeSpan by) => _now += by;
}

public static class TestKeys
{
    public const string PfxPassword = "test-only";

    /// <summary>A throwaway self-signed RSA certificate, base64 PFX. Generated per test run, nothing on disk.</summary>
    public static string NewCertificatePfx(int validDays = 30)
    {
        using var rsa = RSA.Create(2048);
        var req = new CertificateRequest("CN=identity-test-signing", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var cert = req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(validDays));
        return Convert.ToBase64String(cert.Export(X509ContentType.Pfx, PfxPassword));
    }

    public static Dictionary<string, string?> SigningSettings(params string[] pfxs)
    {
        var d = new Dictionary<string, string?> { ["Signing:EncryptionKey"] = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32)) };
        for (var i = 0; i < pfxs.Length; i++)
        {
            d[$"Signing:Certificates:{i}:Pfx"] = pfxs[i];
            d[$"Signing:Certificates:{i}:Password"] = PfxPassword;
        }
        return d;
    }
}

/// <summary>Boots the real app against its own fresh database, so every test starts from migrated seed data.</summary>
public sealed class ApiFactory : WebApplicationFactory<Program>
{
    public const string AdminEmail = "admin@test.example";
    public const string AdminPassword = "an-admin-passphrase-for-tests";

    private readonly Dictionary<string, string?> _settings;
    private readonly string _baseConnectionString;
    private readonly string _databaseName;

    public TestClock Clock { get; } = new();

    public ApiFactory(string baseConnectionString, Dictionary<string, string?>? overrides = null)
    {
        _baseConnectionString = baseConnectionString;
        _databaseName = "identity_" + Guid.NewGuid().ToString("N");
        // A small pool per test database: every test gets its own database, and PostgreSQL only allows ~100 connections.
        var cs = new NpgsqlConnectionStringBuilder(baseConnectionString) { Database = _databaseName, MaxPoolSize = 4 };
        _settings = new()
        {
            ["ConnectionStrings:Identity"] = cs.ConnectionString,
            ["Argon2:MemoryKiB"] = "1024", // fast hashing in tests; production uses the appsettings.json values
            ["Throttle:PerIpPermits"] = "100000",
            ["Throttle:PerAccountPermits"] = "100000",
            ["Server:RequireHttps"] = "false", // TestServer is plain http
            ["Server:Issuer"] = "http://localhost/",
            ["Mfa:EncryptionKey"] = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32)),
            ["Bootstrap:AdminEmail"] = AdminEmail,
            ["Bootstrap:AdminPassword"] = AdminPassword,
            ["OAuthClients:1:ClientId"] = OAuthFlow.ClientId,
            ["OAuthClients:1:RedirectUris:0"] = OAuthFlow.RedirectUri,
        };
        foreach (var (k, v) in TestKeys.SigningSettings(TestKeys.NewCertificatePfx())) _settings[k] = v;
        if (overrides is not null)
            foreach (var (k, v) in overrides) _settings[k] = v;
    }

    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        builder.ConfigureAppConfiguration((_, c) => c.AddInMemoryCollection(_settings));
        // Server-side exceptions are hidden behind problem+json, so surface errors in the test output.
        builder.ConfigureLogging(l => l.AddSimpleConsole().SetMinimumLevel(LogLevel.Error));
        builder.ConfigureTestServices(s =>
        {
            s.RemoveAll<TimeProvider>();
            s.AddSingleton<TimeProvider>(Clock);
        });
    }

    protected override void Dispose(bool disposing)
    {
        base.Dispose(disposing);
        if (!disposing) return;
        if (_settings.GetValueOrDefault("Database:InitializeOnStart") == "false") return; // never created a database
        try
        {
            NpgsqlConnection.ClearAllPools(); // release this test's connections so the next tests can open theirs
            using var admin = new NpgsqlConnection(new NpgsqlConnectionStringBuilder(_baseConnectionString) { Pooling = false }.ConnectionString);
            admin.Open();
            using var cmd = admin.CreateCommand();
            cmd.CommandText = $"DROP DATABASE IF EXISTS \"{_databaseName}\" WITH (FORCE)";
            cmd.ExecuteNonQuery();
        }
        catch (Exception)
        {
            // best effort: a leftover test database is harmless
        }
    }

    public async Task<T> WithDbAsync<T>(Func<IdentityDbContext, Task<T>> action)
    {
        using var scope = Services.CreateScope();
        return await action(scope.ServiceProvider.GetRequiredService<IdentityDbContext>());
    }
}
