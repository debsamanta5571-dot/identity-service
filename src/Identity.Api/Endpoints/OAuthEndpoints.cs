using System.Security.Claims;
using Identity.Api.Data;
using Identity.Api.Security;
using Identity.Api.Startup;
using Microsoft.AspNetCore;
using Microsoft.AspNetCore.Authentication;
using Microsoft.EntityFrameworkCore;
using OpenIddict.Abstractions;
using OpenIddict.Server.AspNetCore;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace Identity.Api.Endpoints;

/// <summary>
/// OpenIddict parses and validates the protocol messages and hands them to these handlers ("passthrough").
/// We decide whether the user is logged in, which scopes they receive, and whether a refresh is still allowed.
/// </summary>
public static class OAuthEndpoints
{
    public static void MapOAuthEndpoints(this IEndpointRouteBuilder app)
    {
        app.MapMethods("/connect/authorize", ["GET", "POST"], Authorize).ExcludeFromDescription();
        app.MapPost("/connect/token", Token).ExcludeFromDescription();
    }

    private static async Task<IResult> Authorize(
        HttpContext http, AuthService auth, IdentityDbContext db,
        IOpenIddictApplicationManager applications, IOpenIddictAuthorizationManager authorizations, CancellationToken ct)
    {
        var request = http.GetOpenIddictServerRequest() ?? throw new InvalidOperationException("The OpenID Connect request cannot be retrieved.");

        var session = await http.AuthenticateAsync(OpenIddictSetup.SessionScheme);
        Guid userId = default;
        var loggedIn = session.Succeeded && Guid.TryParse(session.Principal!.FindFirstValue(Claims.Subject), out userId);

        if (!loggedIn || request.HasPromptValue(PromptValues.Login))
        {
            if (request.HasPromptValue(PromptValues.None))
                return Forbid(Errors.LoginRequired, "The user is not logged in.");

            // Send the user to the login page, then back here. Drop prompt=login so we don't loop.
            var prompt = string.Join(" ", request.GetPromptValues().Remove(PromptValues.Login));
            var parameters = http.Request.HasFormContentType
                ? http.Request.Form.Where(p => p.Key != Parameters.Prompt).ToList()
                : http.Request.Query.Where(p => p.Key != Parameters.Prompt).ToList();
            if (prompt.Length > 0) parameters.Add(new(Parameters.Prompt, prompt));

            return Results.Challenge(
                new AuthenticationProperties { RedirectUri = http.Request.PathBase + http.Request.Path + QueryString.Create(parameters) },
                [OpenIddictSetup.SessionScheme]);
        }

        var user = await db.Users.AsNoTracking().SingleOrDefaultAsync(u => u.Id == userId, ct);
        if (user is null || !user.IsActive)
        {
            await http.SignOutAsync(OpenIddictSetup.SessionScheme);
            return Forbid(Errors.AccessDenied, "The user account is not available.");
        }

        var authenticated = await auth.LoadAsync(user.Id, user.Email, ct);
        var principal = OAuthPrincipal.Create(authenticated, user.DisplayName, request.GetScopes());

        // One permanent authorization per login = one refresh-token family = one "session" in the admin console.
        // (The manager wants the application's internal id, not the public client_id.)
        var application = await applications.FindByClientIdAsync(request.ClientId!, ct)
            ?? throw new InvalidOperationException("The client application cannot be found.");
        var authorization = await authorizations.CreateAsync(
            principal, user.Id.ToString(), (await applications.GetIdAsync(application, ct))!, AuthorizationTypes.Permanent,
            [.. principal.GetScopes()], ct);
        principal.SetAuthorizationId(await authorizations.GetIdAsync(authorization, ct));

        return Results.SignIn(principal, properties: null, OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
    }

    private static async Task<IResult> Token(HttpContext http, AuthService auth, IdentityDbContext db, CancellationToken ct)
    {
        var request = http.GetOpenIddictServerRequest() ?? throw new InvalidOperationException("The OpenID Connect request cannot be retrieved.");
        if (!request.IsAuthorizationCodeGrantType() && !request.IsRefreshTokenGrantType())
            throw new InvalidOperationException("The specified grant type is not supported.");

        // The principal comes from the (already validated, single-use) authorization code or refresh token.
        var result = await http.AuthenticateAsync(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
        var principal = result.Principal!;

        var user = Guid.TryParse(principal.GetClaim(Claims.Subject), out var id)
            ? await db.Users.AsNoTracking().SingleOrDefaultAsync(u => u.Id == id, ct)
            : null;
        if (user is null || !user.IsActive)
            return Forbid(Errors.InvalidGrant, "The user is no longer allowed to sign in.");

        // Re-derive roles/scopes every time, so removing a role takes effect at the next refresh.
        OAuthPrincipal.Refresh(principal, await auth.LoadAsync(user.Id, user.Email, ct), user.DisplayName);

        return Results.SignIn(principal, properties: null, OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
    }

    private static IResult Forbid(string error, string description) =>
        Results.Forbid(
            new AuthenticationProperties(new Dictionary<string, string?>
            {
                [OpenIddictServerAspNetCoreConstants.Properties.Error] = error,
                [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] = description,
            }),
            [OpenIddictServerAspNetCoreDefaults.AuthenticationScheme]);
}
