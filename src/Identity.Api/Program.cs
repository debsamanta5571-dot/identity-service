using System.Globalization;
using System.Threading.RateLimiting;
using Identity.Api.Data;
using Identity.Api.Endpoints;
using Identity.Api.Security;
using Identity.Api.Startup;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Cors.Infrastructure;
using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using OpenIddict.Validation.AspNetCore;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddSingleton(TimeProvider.System);
builder.Services.Configure<Argon2Options>(builder.Configuration.GetSection("Argon2"));
builder.Services.Configure<LockoutOptions>(builder.Configuration.GetSection("Lockout"));
builder.Services.Configure<ThrottleOptions>(builder.Configuration.GetSection("Throttle"));
builder.Services.Configure<BootstrapOptions>(builder.Configuration.GetSection("Bootstrap"));

// The connection string is resolved lazily so it always comes from configuration/environment, never source.
builder.Services.AddDbContext<IdentityDbContext>((sp, o) => o
    .UseNpgsql(sp.GetRequiredService<IConfiguration>().GetConnectionString("Identity")
        ?? throw new InvalidOperationException("ConnectionStrings:Identity is not configured."))
    .UseOpenIddict<Guid>());

builder.Services.AddSingleton<PasswordHasher>();
builder.Services.AddSingleton<AccountRateLimiter>();
builder.Services.AddHttpContextAccessor();
builder.Services.AddSingleton<AuditService>();
builder.Services.AddSingleton<SecretProtector>();
builder.Services.AddScoped<MfaService>();
builder.Services.AddScoped<AuthService>();
builder.Services.AddHostedService<DbInitializer>();
builder.Services.AddScoped<RefreshReuseDetector>();
builder.Services.AddScoped<TokenIssuedAuditHandler>();
builder.Services.AddScoped<RevocationAuditHandler>();

builder.Services.AddIdentityOpenIddict();
builder.Services.AddAntiforgery();

// Bearer tokens (validated by OpenIddict) protect the API; the cookie scheme only backs the login page.
builder.Services.AddAuthentication(OpenIddictValidationAspNetCoreDefaults.AuthenticationScheme)
    .AddCookie(OpenIddictSetup.SessionScheme, o =>
    {
        o.LoginPath = "/account/login";
        o.Cookie.Name = "identity.session";
        o.Cookie.HttpOnly = true;
        o.Cookie.SameSite = SameSiteMode.Lax; // Lax so the cookie survives the redirect back to /connect/authorize
        o.ExpireTimeSpan = TimeSpan.FromHours(8);
        o.SlidingExpiration = false;
    });
builder.Services.AddOptions<CookieAuthenticationOptions>(OpenIddictSetup.SessionScheme).Configure<IConfiguration>((o, cfg) =>
    o.Cookie.SecurePolicy = cfg.GetValue("Server:RequireHttps", true) ? CookieSecurePolicy.Always : CookieSecurePolicy.SameAsRequest);
builder.Services.AddAuthorization(o => o.AddScopePolicies());

// Strict CORS: only the configured console origins, only the verbs/headers it needs, no credentials.
builder.Services.AddOptions<CorsOptions>().Configure<IConfiguration>((o, cfg) =>
    o.AddPolicy("console", p => p
        .WithOrigins(cfg.GetSection("Cors:AllowedOrigins").Get<string[]>() ?? [])
        .WithMethods("GET", "POST", "PUT", "DELETE")
        .WithHeaders("Authorization", "Content-Type")));
builder.Services.AddCors();

// Behind Azure Container Apps ingress the app sees http and the ingress IP. Only enable when ingress is the sole path in.
builder.Services.AddOptions<ForwardedHeadersOptions>().Configure<IConfiguration>((o, cfg) =>
{
    o.ForwardedHeaders = ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedProto;
    if (cfg.GetValue("Server:TrustForwardedHeaders", false))
    {
        o.KnownNetworks.Clear();
        o.KnownProxies.Clear();
    }
});

builder.Services.AddProblemDetails(); // RFC 7807 for errors, 404s and validation failures

builder.Services.AddRateLimiter(o =>
{
    o.AddPolicy("per-ip", http =>
    {
        var t = http.RequestServices.GetRequiredService<IOptions<ThrottleOptions>>().Value;
        return RateLimitPartition.GetFixedWindowLimiter(http.Connection.RemoteIpAddress?.ToString() ?? "unknown",
            _ => new FixedWindowRateLimiterOptions
            {
                PermitLimit = t.PerIpPermits,
                Window = TimeSpan.FromSeconds(t.WindowSeconds),
                QueueLimit = 0,
            });
    });
    o.OnRejected = async (ctx, ct) =>
    {
        if (ctx.Lease.TryGetMetadata(MetadataName.RetryAfter, out var retry))
            ctx.HttpContext.Response.Headers.RetryAfter = Math.Ceiling(retry.TotalSeconds).ToString(CultureInfo.InvariantCulture);
        await Results.Problem(statusCode: 429, title: "Too many requests", detail: "Rate limit exceeded. Try again later.")
            .ExecuteAsync(ctx.HttpContext);
    };
});

var app = builder.Build();

app.UseForwardedHeaders();
app.UseExceptionHandler();
app.UseStatusCodePages();
if (!app.Environment.IsDevelopment()) app.UseHsts();

app.Use(async (ctx, next) =>
{
    var h = ctx.Response.Headers;
    h.XContentTypeOptions = "nosniff";
    h.XFrameOptions = "DENY";
    h["Referrer-Policy"] = "no-referrer";
    h["Content-Security-Policy"] = "default-src 'none'; frame-ancestors 'none'";
    h["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()";
    h.CacheControl = "no-store";
    await next();
});

app.UseCors("console");
app.UseRateLimiter();
app.UseAuthentication();
app.UseAuthorization();

// Liveness only (no database call): a container orchestrator restarts the app if this fails, and a database
// outage should not cause restart loops.
app.MapGet("/health", () => Results.Ok(new { status = "UP" })).ExcludeFromDescription();

app.MapAccountEndpoints();
app.MapOAuthEndpoints();
app.MapMfaEndpoints();
app.MapUserEndpoints();
app.MapRoleEndpoints();
app.MapSessionEndpoints();
app.MapAuditEndpoints();

app.Run();

public partial class Program;
