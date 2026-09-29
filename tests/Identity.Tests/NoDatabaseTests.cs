using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Identity.Tests.Infrastructure;
using Microsoft.IdentityModel.Tokens;

namespace Identity.Tests;

/// <summary>
/// Everything that works without touching PostgreSQL: protocol metadata, signing keys, CORS, headers,
/// the login page. These run anywhere, including machines without Docker.
/// </summary>
public sealed class NoDatabaseTests : IDisposable
{
    private readonly ApiFactory _factory = new("Host=unused;Username=unused", new()
    {
        ["Database:InitializeOnStart"] = "false",
        ["Cors:AllowedOrigins:0"] = "http://localhost:4200",
    });
    private readonly HttpClient _client;

    public NoDatabaseTests() => _client = _factory.CreateClient();

    public void Dispose()
    {
        _client.Dispose();
        _factory.Dispose();
    }

    [Fact]
    public async Task Discovery_document_is_served_and_lists_the_expected_endpoints()
    {
        var res = await _client.GetAsync("/.well-known/openid-configuration");
        Assert.Equal(HttpStatusCode.OK, res.StatusCode);
        var doc = await res.Content.ReadFromJsonAsync<JsonElement>();

        Assert.Equal("http://localhost/", doc.GetProperty("issuer").GetString());
        Assert.EndsWith("/connect/authorize", doc.GetProperty("authorization_endpoint").GetString());
        Assert.EndsWith("/connect/token", doc.GetProperty("token_endpoint").GetString());
        Assert.EndsWith("/connect/revoke", doc.GetProperty("revocation_endpoint").GetString());
        Assert.Equal(["S256"], doc.GetProperty("code_challenge_methods_supported").EnumerateArray().Select(x => x.GetString()));
        Assert.Equal(["authorization_code", "refresh_token"],
            doc.GetProperty("grant_types_supported").EnumerateArray().Select(x => x.GetString()!).Order());
    }

    [Fact]
    public async Task Jwks_contains_only_public_rsa_keys()
    {
        var keys = new JsonWebKeySet(await _client.GetStringAsync("/.well-known/jwks")).Keys;
        Assert.Single(keys);
        Assert.Equal("RSA", keys[0].Kty);
        Assert.Equal("sig", keys[0].Use);
        Assert.True(string.IsNullOrEmpty(keys[0].D) && string.IsNullOrEmpty(keys[0].P)); // no private key material
    }

    [Fact]
    public async Task Jwks_publishes_every_configured_key_during_rotation()
    {
        var oldPfx = TestKeys.NewCertificatePfx(30);
        var newPfx = TestKeys.NewCertificatePfx(90);
        using var f = new ApiFactory("Host=unused;Username=unused", new(TestKeys.SigningSettings(oldPfx, newPfx))
        {
            ["Database:InitializeOnStart"] = "false",
        });
        using var c = f.CreateClient();

        var keys = new JsonWebKeySet(await c.GetStringAsync("/.well-known/jwks")).Keys;
        Assert.Equal(2, keys.Count);
        Assert.Equal(2, keys.Select(k => k.Kid).Distinct().Count());
    }

    [Fact]
    public async Task Api_requires_a_bearer_token_and_answers_with_problem_json()
    {
        var res = await _client.GetAsync("/api/roles");
        Assert.Equal(HttpStatusCode.Unauthorized, res.StatusCode);
    }

    [Fact]
    public async Task Unknown_routes_return_problem_json()
    {
        var res = await _client.GetAsync("/nope");
        Assert.Equal(HttpStatusCode.NotFound, res.StatusCode);
        Assert.Equal("application/problem+json", res.Content.Headers.ContentType?.MediaType);
    }

    [Fact]
    public async Task Cors_allows_the_console_origin_and_nothing_else()
    {
        var allowed = new HttpRequestMessage(HttpMethod.Get, "/.well-known/jwks");
        allowed.Headers.Add("Origin", "http://localhost:4200");
        Assert.Equal("http://localhost:4200", (await _client.SendAsync(allowed)).Headers.GetValues("Access-Control-Allow-Origin").Single());

        var evil = new HttpRequestMessage(HttpMethod.Get, "/.well-known/jwks");
        evil.Headers.Add("Origin", "https://evil.example");
        Assert.False((await _client.SendAsync(evil)).Headers.Contains("Access-Control-Allow-Origin"));

        var preflight = new HttpRequestMessage(HttpMethod.Options, "/api/users");
        preflight.Headers.Add("Origin", "https://evil.example");
        preflight.Headers.Add("Access-Control-Request-Method", "POST");
        Assert.False((await _client.SendAsync(preflight)).Headers.Contains("Access-Control-Allow-Origin"));
    }

    [Fact]
    public async Task Login_page_renders_with_antiforgery_token_and_a_tight_csp()
    {
        var res = await _client.GetAsync("/account/login?returnUrl=%2Fconnect%2Fauthorize");
        var html = await res.Content.ReadAsStringAsync();

        Assert.Equal(HttpStatusCode.OK, res.StatusCode);
        Assert.Contains("__RequestVerificationToken", html);
        Assert.Contains("name=\"password\" type=\"password\"", html);
        var csp = res.Headers.GetValues("Content-Security-Policy").Single();
        Assert.Contains("frame-ancestors 'none'", csp);
        Assert.Contains("form-action 'self' http://localhost:4200", csp); // the post-login redirect ends at the console
        Assert.DoesNotContain("script-src", csp);          // no scripts allowed at all
        Assert.Equal("DENY", res.Headers.GetValues("X-Frame-Options").Single());
    }

    [Fact]
    public async Task Login_page_html_encodes_the_return_url()
    {
        var res = await _client.GetAsync("/account/login?returnUrl=%22%3E%3Cscript%3Ealert(1)%3C/script%3E");
        Assert.DoesNotContain("<script>alert", await res.Content.ReadAsStringAsync());
    }

    [Fact]
    public async Task Logout_redirects_only_to_configured_console_origins()
    {
        using var c = _factory.CreateClient(new Microsoft.AspNetCore.Mvc.Testing.WebApplicationFactoryClientOptions { AllowAutoRedirect = false });

        var ok = await c.GetAsync("/account/logout?post_logout_redirect_uri=" + Uri.EscapeDataString("http://localhost:4200/"));
        Assert.Equal(HttpStatusCode.Redirect, ok.StatusCode);
        Assert.Equal("http://localhost:4200/", ok.Headers.Location!.ToString());

        foreach (var evil in new[] { "https://evil.example/", "http://localhost:4200.evil.example/", "//evil.example", "javascript:alert(1)" })
        {
            var res = await c.GetAsync("/account/logout?post_logout_redirect_uri=" + Uri.EscapeDataString(evil));
            Assert.Equal(HttpStatusCode.OK, res.StatusCode);
            Assert.Null(res.Headers.Location);
        }
    }

    [Fact]
    public async Task Health_is_public_and_does_not_need_the_database()
    {
        var res = await _client.GetAsync("/health");
        Assert.Equal(HttpStatusCode.OK, res.StatusCode);
        Assert.Contains("UP", await res.Content.ReadAsStringAsync());
    }
}
