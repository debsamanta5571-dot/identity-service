using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Web;
using Microsoft.AspNetCore.Mvc.Testing;

namespace Identity.Tests.Infrastructure;

public sealed record TokenSet(string AccessToken, string? RefreshToken, string? IdToken);

/// <summary>Drives the real authorization code + PKCE flow over HTTP, the way a browser app would.</summary>
public sealed partial class OAuthFlow(ApiFactory factory)
{
    public const string ClientId = "test-client";
    public const string RedirectUri = "http://localhost/callback";
    public const string DefaultScope = "openid offline_access accounts:read accounts:write transfers:read transfers:write audit:read users:admin";

    [GeneratedRegex("name=\"__RequestVerificationToken\" value=\"([^\"]+)\"")]
    private static partial Regex AntiforgeryField();

    public HttpClient NewClient() =>
        factory.CreateClient(new WebApplicationFactoryClientOptions { AllowAutoRedirect = false }); // own cookie jar per client

    public static (string Verifier, string Challenge) Pkce()
    {
        var verifier = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32)).TrimEnd('=').Replace('+', '-').Replace('/', '_');
        var challenge = Convert.ToBase64String(SHA256.HashData(Encoding.ASCII.GetBytes(verifier))).TrimEnd('=').Replace('+', '-').Replace('/', '_');
        return (verifier, challenge);
    }

    /// <summary>Loads the login page (cookie + antiforgery token) and posts the form.</summary>
    public async Task<HttpResponseMessage> FormLogin(HttpClient c, string email, string password, string? code = null, string returnUrl = "/")
    {
        var page = await c.GetAsync("/account/login?returnUrl=" + Uri.EscapeDataString(returnUrl));
        var html = await page.Content.ReadAsStringAsync();
        var token = WebUtility.HtmlDecode(AntiforgeryField().Match(html).Groups[1].Value);
        return await c.PostAsync("/account/login", new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["__RequestVerificationToken"] = token,
            ["returnUrl"] = returnUrl,
            ["email"] = email,
            ["password"] = password,
            ["code"] = code ?? "",
        }));
    }

    public static string AuthorizeUrl(string challenge, string scope = DefaultScope, string state = "state-1", string? method = "S256") =>
        "/connect/authorize?client_id=" + ClientId + "&response_type=code&redirect_uri=" + Uri.EscapeDataString(RedirectUri)
        + "&scope=" + Uri.EscapeDataString(scope) + "&state=" + state
        + (challenge.Length > 0 ? "&code_challenge=" + challenge : "")
        + (method is null ? "" : "&code_challenge_method=" + method);

    /// <summary>authorize -> login page -> login -> authorize again -> redirect with ?code=</summary>
    public async Task<string> GetAuthorizationCode(HttpClient c, string email, string password, string challenge, string scope = DefaultScope, string? totp = null)
    {
        var first = await c.GetAsync(AuthorizeUrl(challenge, scope));
        Assert.True(first.StatusCode == HttpStatusCode.Redirect, $"authorize returned {(int)first.StatusCode}: {await first.Content.ReadAsStringAsync()}");
        var loginUri = new Uri(new Uri("http://localhost"), first.Headers.Location!);
        var returnUrl = HttpUtility.ParseQueryString(loginUri.Query)["ReturnUrl"]!;

        var login = await FormLogin(c, email, password, totp, returnUrl);
        Assert.True(login.StatusCode == HttpStatusCode.Redirect, $"login failed: {(int)login.StatusCode} {await login.Content.ReadAsStringAsync()}");

        var second = await c.GetAsync(login.Headers.Location);
        Assert.True(second.StatusCode == HttpStatusCode.Redirect, $"authorize after login returned {(int)second.StatusCode}: {await second.Content.ReadAsStringAsync()}");
        var query = HttpUtility.ParseQueryString(second.Headers.Location!.Query);
        Assert.True(query["code"] is not null, "no code in redirect: " + second.Headers.Location);
        return query["code"]!;
    }

    public Task<HttpResponseMessage> Exchange(HttpClient c, string code, string verifier) =>
        c.PostAsync("/connect/token", new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["grant_type"] = "authorization_code",
            ["client_id"] = ClientId,
            ["code"] = code,
            ["redirect_uri"] = RedirectUri,
            ["code_verifier"] = verifier,
        }));

    public Task<HttpResponseMessage> Refresh(HttpClient c, string refreshToken) =>
        c.PostAsync("/connect/token", new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["grant_type"] = "refresh_token",
            ["client_id"] = ClientId,
            ["refresh_token"] = refreshToken,
        }));

    public Task<HttpResponseMessage> Revoke(HttpClient c, string token, string hint = "refresh_token") =>
        c.PostAsync("/connect/revoke", new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["client_id"] = ClientId,
            ["token"] = token,
            ["token_type_hint"] = hint,
        }));

    public static async Task<TokenSet> ReadTokens(HttpResponseMessage r)
    {
        var body = await r.Content.ReadAsStringAsync();
        Assert.True(r.StatusCode == HttpStatusCode.OK, $"token endpoint returned {(int)r.StatusCode}: {body}");
        var json = JsonDocument.Parse(body).RootElement;
        return new TokenSet(
            json.GetProperty("access_token").GetString()!,
            json.TryGetProperty("refresh_token", out var rt) ? rt.GetString() : null,
            json.TryGetProperty("id_token", out var it) ? it.GetString() : null);
    }

    /// <summary>The whole flow in one call.</summary>
    public async Task<TokenSet> SignIn(string email, string password, string scope = DefaultScope, string? totp = null)
    {
        var c = NewClient();
        var (verifier, challenge) = Pkce();
        var code = await GetAuthorizationCode(c, email, password, challenge, scope, totp);
        return await ReadTokens(await Exchange(c, code, verifier));
    }
}
