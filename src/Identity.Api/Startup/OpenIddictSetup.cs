using Identity.Api.Data;
using Identity.Api.Security;
using OpenIddict.Server;
using OpenIddict.Server.AspNetCore;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace Identity.Api.Startup;

public static class OpenIddictSetup
{
    public const string SessionScheme = "Identity.Session";

    /// <summary>
    /// OpenIddict owns the protocol layer (request parsing, PKCE verification, JWT signing, JWKS, discovery,
    /// token storage). Everything that decides *who* gets a token is ours: see OAuthEndpoints and OAuthPrincipal.
    /// </summary>
    public static IServiceCollection AddIdentityOpenIddict(this IServiceCollection services)
    {
        services.AddOpenIddict()
            .AddCore(o => o.UseEntityFrameworkCore().UseDbContext<IdentityDbContext>().ReplaceDefaultEntities<Guid>())
            .AddServer(o =>
            {
                o.SetAuthorizationEndpointUris("/connect/authorize")
                 .SetTokenEndpointUris("/connect/token")
                 .SetRevocationEndpointUris("/connect/revoke");

                // Authorization code + PKCE and refresh tokens only. No implicit, password or client-credentials grants.
                o.AllowAuthorizationCodeFlow().AllowRefreshTokenFlow().RequireProofKeyForCodeExchange();

                o.RegisterScopes([.. OAuthPrincipal.StandardScopes, .. SeedData.Scopes.Select(s => s.Name)]);

                // Access tokens stay signed-only JWTs so other services (the Java ledger) can verify them via JWKS.
                o.DisableAccessTokenEncryption();

                o.UseAspNetCore()
                 .EnableAuthorizationEndpointPassthrough()
                 .EnableTokenEndpointPassthrough();

                // After the tokens are generated (orders 100k-112k) and before the response is written (500k), which ends the pipeline.
                o.AddEventHandler<OpenIddictServerEvents.ProcessSignInContext>(b =>
                    b.UseScopedHandler<TokenIssuedAuditHandler>().SetOrder(200_000));
                o.AddEventHandler<OpenIddictServerEvents.ApplyRevocationResponseContext>(b =>
                    b.UseScopedHandler<RevocationAuditHandler>());

                o.AddEventHandler<OpenIddictServerEvents.ValidateTokenContext>(b =>
                    b.UseScopedHandler<RefreshReuseDetector>()
                     .SetOrder(OpenIddictServerHandlers.Protection.ValidateTokenEntry.Descriptor.Order - 1));
            })
            .AddValidation(o =>
            {
                o.UseLocalServer();
                o.UseAspNetCore();
                o.AddAudiences(OAuthPrincipal.IdentityAudience);
            });

        // Values that may differ per environment (and per test) are read through DI, not at startup.
        services.AddOptions<OpenIddictServerOptions>().Configure<IConfiguration, IHostEnvironment>((o, cfg, env) =>
        {
            o.Issuer = new Uri(cfg["Server:Issuer"] ?? "https://localhost:5001/");
            o.AccessTokenLifetime = TimeSpan.FromMinutes(cfg.GetValue("Tokens:AccessTokenMinutes", 10));
            o.RefreshTokenLifetime = TimeSpan.FromDays(cfg.GetValue("Tokens:RefreshTokenDays", 7));
            o.AuthorizationCodeLifetime = TimeSpan.FromMinutes(2);
            o.RefreshTokenReuseLeeway = null; // strict: a redeemed refresh token is never accepted again
            o.CodeChallengeMethods.Remove(CodeChallengeMethods.Plain); // OpenIddict allows "plain" by default; S256 only
            SigningKeys.Apply(o, cfg, env);
        });
        services.AddOptions<OpenIddictServerAspNetCoreOptions>().Configure<IConfiguration>((o, cfg) =>
            o.DisableTransportSecurityRequirement = !cfg.GetValue("Server:RequireHttps", true));

        return services;
    }
}
