using System.Globalization;
using System.Net;
using System.Security.Claims;
using Identity.Api.Security;
using Identity.Api.Startup;
using Microsoft.AspNetCore.Antiforgery;
using Microsoft.AspNetCore.Authentication;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace Identity.Api.Endpoints;

/// <summary>The interactive login page used by the authorization code flow. Plain server-rendered HTML.</summary>
public static class AccountEndpoints
{
    public static void MapAccountEndpoints(this IEndpointRouteBuilder app)
    {
        var g = app.MapGroup("/account").ExcludeFromDescription();

        g.MapGet("/login", (HttpContext http, IAntiforgery antiforgery, string? returnUrl) =>
            Page(http, antiforgery, returnUrl, email: "", error: null, mfa: false));

        g.MapPost("/login", Login).RequireRateLimiting("per-ip");

        // Ends the login-page session (the cookie). Redirects only to configured console origins, never to arbitrary URLs.
        g.MapGet("/logout", async (HttpContext http, IConfiguration config, string? post_logout_redirect_uri) =>
        {
            await http.SignOutAsync(OpenIddictSetup.SessionScheme);
            var allowed = config.GetSection("Cors:AllowedOrigins").Get<string[]>() ?? [];
            return Uri.TryCreate(post_logout_redirect_uri, UriKind.Absolute, out var target)
                   && allowed.Contains(target.GetLeftPart(UriPartial.Authority), StringComparer.OrdinalIgnoreCase)
                ? Results.Redirect(target.ToString())
                : Results.Text("You have been signed out.");
        });
    }

    private static async Task<IResult> Login(
        HttpContext http, IAntiforgery antiforgery, AuthService auth, AccountRateLimiter limiter, AuditService audit, CancellationToken ct)
    {
        try { await antiforgery.ValidateRequestAsync(http); }
        catch (AntiforgeryValidationException) { return Results.Problem(statusCode: 400, title: "Invalid form token"); }

        var form = await http.Request.ReadFormAsync(ct);
        var email = Validation.NormalizeEmail(form["email"].ToString());
        var password = form["password"].ToString();
        var returnUrl = SafeReturnUrl(form["returnUrl"].ToString());

        if (email.Length == 0 || password.Length is 0 or > Validation.MaxPasswordLength)
            return Page(http, antiforgery, returnUrl, email, "Email and password are required.", mfa: false, StatusCodes.Status400BadRequest);

        if (!limiter.TryAcquire(email, out var retryAfter))
        {
            await audit.RecordAsync(AuditEvents.LoginFailure, false, details: new { email, reason = "rate_limited" }, ct: ct);
            http.Response.Headers.RetryAfter = Math.Ceiling(retryAfter.TotalSeconds).ToString(CultureInfo.InvariantCulture);
            return Page(http, antiforgery, returnUrl, email, "Too many attempts. Try again later.", mfa: false, StatusCodes.Status429TooManyRequests);
        }

        var result = await auth.LoginAsync(email, password, form["code"].ToString(), ct);
        if (result.Status == LoginStatus.MfaRequired)
        {
            await audit.RecordAsync(AuditEvents.LoginMfaRequired, true, userId: result.UserId, details: new { email }, ct: ct);
            return Page(http, antiforgery, returnUrl, email, "Enter the code from your authenticator app (or a recovery code) and sign in again.", mfa: true);
        }
        if (result.Status != LoginStatus.Success)
        {
            await audit.RecordAsync(AuditEvents.LoginFailure, false, userId: result.UserId, details: new { email, reason = result.Reason }, ct: ct);
            return Page(http, antiforgery, returnUrl, email, "The email or password is incorrect.", mfa: false, StatusCodes.Status401Unauthorized);
        }

        if (result.Mfa == MfaMethod.Recovery)
            await audit.RecordAsync(AuditEvents.MfaRecoveryCodeUsed, true, userId: result.UserId, ct: ct);
        await audit.RecordAsync(AuditEvents.LoginSuccess, true, userId: result.UserId, details: new { email, mfa = result.Mfa?.ToString().ToLowerInvariant() }, ct: ct);

        var identity = new ClaimsIdentity(OpenIddictSetup.SessionScheme, Claims.Name, Claims.Role);
        identity.AddClaim(new Claim(Claims.Subject, result.User!.UserId.ToString()));
        identity.AddClaim(new Claim(Claims.Name, result.User.Email));
        await http.SignInAsync(OpenIddictSetup.SessionScheme, new ClaimsPrincipal(identity));

        return Results.LocalRedirect(returnUrl);
    }

    /// <summary>Only same-site relative paths are allowed, so the login page can't be used as an open redirect.</summary>
    private static string SafeReturnUrl(string? url) =>
        !string.IsNullOrEmpty(url) && url[0] == '/' && (url.Length == 1 || (url[1] != '/' && url[1] != '\\')) ? url : "/";

    private static IResult Page(HttpContext http, IAntiforgery antiforgery, string? returnUrl, string email, string? error, bool mfa, int status = 200)
    {
        var tokens = antiforgery.GetAndStoreTokens(http);
        static string enc(string? s) => WebUtility.HtmlEncode(s) ?? "";
        var html = $$"""
            <!doctype html><html lang="en"><head><meta charset="utf-8"><title>Sign in</title>
            <meta name="viewport" content="width=device-width,initial-scale=1">
            <style>body{font:16px system-ui;max-width:22rem;margin:4rem auto;padding:0 1rem}label{display:block;margin-top:1rem}
            input{width:100%;padding:.5rem;box-sizing:border-box}button{margin-top:1.5rem;padding:.6rem 1rem}.err{color:#b00020}</style></head>
            <body><h1>Sign in</h1>
            {{(error is null ? "" : $"<p class=\"err\" role=\"alert\">{enc(error)}</p>")}}
            <form method="post" action="/account/login">
              <input type="hidden" name="{{enc(tokens.FormFieldName!)}}" value="{{enc(tokens.RequestToken!)}}">
              <input type="hidden" name="returnUrl" value="{{enc(SafeReturnUrl(returnUrl))}}">
              <label>Email <input name="email" type="email" autocomplete="username" required value="{{enc(email)}}"></label>
              <label>Password <input name="password" type="password" autocomplete="current-password" required></label>
              <label>Authentication code (only if MFA is enabled) <input name="code" inputmode="numeric" autocomplete="one-time-code"></label>
              <button type="submit">Sign in</button>
            </form></body></html>
            """;
        // This page needs inline style and a form post to itself; everything else keeps the strict API policy.
        // Browsers also apply form-action to the redirects that follow the post, and a successful sign-in ends by
        // redirecting to the client app, so the configured client origins must be allowed as form targets too.
        var clientOrigins = http.RequestServices.GetRequiredService<IConfiguration>().GetSection("Cors:AllowedOrigins").Get<string[]>() ?? [];
        http.Response.Headers.ContentSecurityPolicy =
            $"default-src 'none'; style-src 'unsafe-inline'; form-action 'self' {string.Join(' ', clientOrigins)}; frame-ancestors 'none'";
        return Results.Content(html, "text/html; charset=utf-8", statusCode: status);
    }
}
