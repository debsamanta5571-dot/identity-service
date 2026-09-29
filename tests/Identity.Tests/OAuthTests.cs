using System.Net;
using System.Net.Http.Json;
using Identity.Tests.Infrastructure;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using OpenIddict.EntityFrameworkCore.Models;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace Identity.Tests;

public class OAuthTests(PostgresFixture pg) : ApiTestBase(pg)
{
    private static async Task<JsonWebKeySet> Jwks(HttpClient c)
    {
        var doc = await Json(await c.GetAsync("/.well-known/openid-configuration"));
        return new JsonWebKeySet(await c.GetStringAsync(doc.GetProperty("jwks_uri").GetString()));
    }

    private static Task<TokenValidationResult> Validate(string token, JsonWebKeySet keys) =>
        new JsonWebTokenHandler().ValidateTokenAsync(token, new TokenValidationParameters
        {
            IssuerSigningKeys = keys.GetSigningKeys(),
            ValidIssuer = "http://localhost/",
            ValidAudience = "ledger-api",
            ClockSkew = TimeSpan.Zero,
        });

    // ---- discovery, JWKS, signing -------------------------------------------------------------------------

    [Fact]
    public async Task Discovery_advertises_only_code_flow_with_pkce_and_refresh()
    {
        var doc = await Json(await Client.GetAsync("/.well-known/openid-configuration"));
        Assert.Equal("http://localhost/", doc.GetProperty("issuer").GetString());
        string[] Strings(string p) => doc.GetProperty(p).EnumerateArray().Select(x => x.GetString()!).ToArray();

        Assert.Equal(["authorization_code", "refresh_token"], Strings("grant_types_supported").Order());
        Assert.Equal(["code"], Strings("response_types_supported"));
        Assert.Equal(["S256"], Strings("code_challenge_methods_supported"));
        Assert.Contains("RS256", Strings("id_token_signing_alg_values_supported"));
        Assert.True(doc.TryGetProperty("revocation_endpoint", out _));
        Assert.Contains("transfers:write", Strings("scopes_supported"));
    }

    [Fact]
    public async Task Jwks_publishes_rsa_signing_keys()
    {
        var keys = (await Jwks(Client)).Keys;
        Assert.NotEmpty(keys);
        Assert.All(keys, k =>
        {
            Assert.Equal("RSA", k.Kty);
            Assert.Equal("sig", k.Use);
            Assert.False(string.IsNullOrEmpty(k.Kid));
            Assert.True(string.IsNullOrEmpty(k.D)); // public parts only
        });
    }

    [Fact]
    public async Task Access_token_is_an_rs256_jwt_that_verifies_against_the_jwks()
    {
        var token = (await OAuth.SignIn(ApiFactory.AdminEmail, ApiFactory.AdminPassword)).AccessToken;
        var jwt = Jwt(token);
        var keys = await Jwks(Client);

        Assert.Equal("RS256", jwt.Alg);
        Assert.Equal("at+jwt", jwt.Typ); // RFC 9068 access-token type; the ledger only accepts this typ
        Assert.Contains(keys.Keys, k => k.Kid == jwt.Kid);
        Assert.Contains("ledger-api", jwt.Audiences);
        Assert.Equal("http://localhost/", jwt.Issuer);
        Assert.True((await Validate(token, keys)).IsValid);
    }

    [Fact]
    public async Task Access_tokens_are_short_lived()
    {
        var jwt = Jwt((await OAuth.SignIn(ApiFactory.AdminEmail, ApiFactory.AdminPassword)).AccessToken);
        Assert.InRange(jwt.ValidTo - jwt.IssuedAt, TimeSpan.FromMinutes(1), TimeSpan.FromMinutes(15));
    }

    [Fact]
    public async Task Tampered_token_is_rejected_by_the_api()
    {
        var token = (await OAuth.SignIn(ApiFactory.AdminEmail, ApiFactory.AdminPassword)).AccessToken;
        var tampered = token[..^4] + (token.EndsWith("AAAA") ? "BBBB" : "AAAA");
        using var c = BearerClient(tampered);
        Assert.Equal(HttpStatusCode.Unauthorized, (await c.GetAsync("/api/roles")).StatusCode);
    }

    [Fact]
    public async Task Key_rotation_new_key_signs_and_old_tokens_still_verify()
    {
        var oldPfx = TestKeys.NewCertificatePfx(validDays: 30);
        var newPfx = TestKeys.NewCertificatePfx(validDays: 90); // expires last, so OpenIddict signs with it

        using var before = new ApiFactory(Pg.ConnectionString, TestKeys.SigningSettings(oldPfx));
        using var after = new ApiFactory(Pg.ConnectionString, TestKeys.SigningSettings(oldPfx, newPfx));

        var t1 = (await new OAuthFlow(before).SignIn(ApiFactory.AdminEmail, ApiFactory.AdminPassword)).AccessToken;
        var t2 = (await new OAuthFlow(after).SignIn(ApiFactory.AdminEmail, ApiFactory.AdminPassword)).AccessToken;

        var keysBefore = await Jwks(before.CreateClient());
        var keysAfter = await Jwks(after.CreateClient());

        Assert.Single(keysBefore.Keys);
        Assert.Equal(2, keysAfter.Keys.Count);                       // both keys published during the overlap
        Assert.NotEqual(Jwt(t1).Kid, Jwt(t2).Kid);                   // new tokens use the new key
        Assert.Contains(keysAfter.Keys, k => k.Kid == Jwt(t1).Kid);  // old key still published
        Assert.True((await Validate(t1, keysAfter)).IsValid);        // token signed before rotation still verifies
        Assert.True((await Validate(t2, keysAfter)).IsValid);
        Assert.False((await Validate(t2, keysBefore)).IsValid);      // and the old key set does not know the new key
    }

    // ---- authorization code + PKCE ------------------------------------------------------------------------

    /// <summary>OpenIddict reports it either as a redirect back to the client with error=... or as a 400 error page.</summary>
    private static async Task AssertRejectedAsInvalidRequest(HttpResponseMessage res)
    {
        if (res.StatusCode == HttpStatusCode.Redirect) Assert.Contains("error=invalid_request", res.Headers.Location!.Query);
        else
        {
            Assert.Equal(HttpStatusCode.BadRequest, res.StatusCode);
            Assert.Contains("invalid_request", await res.Content.ReadAsStringAsync());
        }
    }

    [Fact]
    public async Task Authorization_request_without_pkce_is_rejected()
    {
        var res = await OAuth.NewClient().GetAsync(OAuthFlow.AuthorizeUrl(challenge: "", method: null));
        await AssertRejectedAsInvalidRequest(res);
    }

    [Fact]
    public async Task Plain_pkce_method_is_rejected()
    {
        var (_, challenge) = OAuthFlow.Pkce();
        var res = await OAuth.NewClient().GetAsync(OAuthFlow.AuthorizeUrl(challenge, method: "plain"));
        await AssertRejectedAsInvalidRequest(res);
    }

    [Fact]
    public async Task Unregistered_redirect_uri_is_never_redirected_to()
    {
        var (_, challenge) = OAuthFlow.Pkce();
        var url = OAuthFlow.AuthorizeUrl(challenge).Replace(Uri.EscapeDataString(OAuthFlow.RedirectUri), Uri.EscapeDataString("https://evil.example/cb"));
        var res = await OAuth.NewClient().GetAsync(url);
        Assert.NotEqual("evil.example", res.Headers.Location?.Host);
    }

    [Fact]
    public async Task Wrong_code_verifier_is_invalid_grant()
    {
        var c = OAuth.NewClient();
        var (_, challenge) = OAuthFlow.Pkce();
        var code = await OAuth.GetAuthorizationCode(c, ApiFactory.AdminEmail, ApiFactory.AdminPassword, challenge);

        var res = await OAuth.Exchange(c, code, "not-the-verifier-not-the-verifier-not-the-verifier");
        Assert.Equal(HttpStatusCode.BadRequest, res.StatusCode);
        Assert.Equal("invalid_grant", (await Json(res)).GetProperty("error").GetString());
    }

    [Fact]
    public async Task Authorization_code_is_single_use()
    {
        var c = OAuth.NewClient();
        var (verifier, challenge) = OAuthFlow.Pkce();
        var code = await OAuth.GetAuthorizationCode(c, ApiFactory.AdminEmail, ApiFactory.AdminPassword, challenge);

        Assert.Equal(HttpStatusCode.OK, (await OAuth.Exchange(c, code, verifier)).StatusCode);
        Assert.Equal(HttpStatusCode.BadRequest, (await OAuth.Exchange(c, code, verifier)).StatusCode);
    }

    [Fact]
    public async Task Issued_scopes_are_requested_scopes_intersected_with_the_users_role_scopes()
    {
        var email = await NewUserEmail("auditor"); // accounts:read, transfers:read, audit:read
        var token = await OAuth.SignIn(email, GoodPassword, "openid accounts:read transfers:write users:admin");

        var scopes = ScopesOf(token.AccessToken);
        Assert.Contains("accounts:read", scopes);
        Assert.DoesNotContain("transfers:write", scopes); // requested but not granted by the role
        Assert.DoesNotContain("users:admin", scopes);
    }

    [Fact]
    public async Task Access_token_carries_the_display_name_only_with_profile_and_never_the_email()
    {
        var email = await NewUserEmail("operator");

        var withProfile = Jwt((await OAuth.SignIn(email, GoodPassword, "openid profile accounts:read")).AccessToken);
        Assert.True(withProfile.TryGetClaim("name", out var name)); // lets APIs label who acted (ledger audit trail)
        Assert.False(string.IsNullOrEmpty(name.Value));
        Assert.False(withProfile.TryGetClaim("email", out _));

        var withoutProfile = Jwt((await OAuth.SignIn(email, GoodPassword, "openid accounts:read")).AccessToken);
        Assert.False(withoutProfile.TryGetClaim("name", out _));
        Assert.False(withoutProfile.TryGetClaim("email", out _));
    }

    [Fact]
    public async Task Api_accepts_a_token_with_the_scope_and_rejects_one_without()
    {
        var operatorEmail = await NewUserEmail("operator");
        using var noAdmin = BearerClient((await OAuth.SignIn(operatorEmail, GoodPassword)).AccessToken);
        Assert.Equal(HttpStatusCode.Forbidden, (await noAdmin.GetAsync("/api/roles")).StatusCode);

        Assert.Equal(HttpStatusCode.OK, (await Api.GetAsync("/api/roles")).StatusCode);
    }

    // ---- refresh rotation and reuse detection --------------------------------------------------------------

    [Fact]
    public async Task Refresh_rotates_the_refresh_token()
    {
        var first = await OAuth.SignIn(ApiFactory.AdminEmail, ApiFactory.AdminPassword);
        var second = await OAuthFlow.ReadTokens(await OAuth.Refresh(OAuth.NewClient(), first.RefreshToken!));

        Assert.NotNull(second.RefreshToken);
        Assert.NotEqual(first.RefreshToken, second.RefreshToken);
        Assert.NotEqual(first.AccessToken, second.AccessToken);
    }

    [Fact]
    public async Task Replaying_an_old_refresh_token_revokes_the_whole_family()
    {
        var email = await NewUserEmail("operator");
        var first = await OAuth.SignIn(email, GoodPassword);
        var c = OAuth.NewClient();

        var second = await OAuthFlow.ReadTokens(await OAuth.Refresh(c, first.RefreshToken!));
        var third = await OAuthFlow.ReadTokens(await OAuth.Refresh(c, second.RefreshToken!)); // legitimate chain: 1 -> 2 -> 3

        // attacker (or buggy client) replays token 1, which was already redeemed
        var replay = await OAuth.Refresh(c, first.RefreshToken!);
        Assert.Equal(HttpStatusCode.BadRequest, replay.StatusCode);
        Assert.Equal("invalid_grant", (await Json(replay)).GetProperty("error").GetString());

        // the newest, previously valid token is dead too: the whole family is gone
        Assert.Equal(HttpStatusCode.BadRequest, (await OAuth.Refresh(c, third.RefreshToken!)).StatusCode);

        var userId = (await Db(db => db.Users.Where(u => u.Email == email).Select(u => u.Id).SingleAsync())).ToString();
        var (validTokens, validAuthorizations) = await Db(async db => (
            await db.Set<OpenIddictEntityFrameworkCoreToken<Guid>>().CountAsync(t => t.Subject == userId && t.Status == Statuses.Valid),
            await db.Set<OpenIddictEntityFrameworkCoreAuthorization<Guid>>().CountAsync(a => a.Subject == userId && a.Status == Statuses.Valid)));
        Assert.Equal((0, 0), (validTokens, validAuthorizations));
    }

    [Fact]
    public async Task Reuse_in_one_session_does_not_touch_the_users_other_sessions()
    {
        var email = await NewUserEmail("operator");
        var sessionA = await OAuth.SignIn(email, GoodPassword);
        var sessionB = await OAuth.SignIn(email, GoodPassword);
        var c = OAuth.NewClient();

        await OAuth.Refresh(c, sessionA.RefreshToken!);
        await OAuth.Refresh(c, sessionA.RefreshToken!); // replay in session A

        Assert.Equal(HttpStatusCode.OK, (await OAuth.Refresh(c, sessionB.RefreshToken!)).StatusCode);
    }

    [Fact]
    public async Task Role_changes_take_effect_at_the_next_refresh()
    {
        var email = await NewUserEmail("operator");
        var id = await Db(db => db.Users.Where(u => u.Email == email).Select(u => u.Id).SingleAsync());
        var first = await OAuth.SignIn(email, GoodPassword);
        Assert.Contains("transfers:write", ScopesOf(first.AccessToken));

        await Api.PutAsJsonAsync($"/api/users/{id}/roles", new { roles = new[] { "auditor" } });

        var refreshed = await OAuthFlow.ReadTokens(await OAuth.Refresh(OAuth.NewClient(), first.RefreshToken!));
        var scopes = ScopesOf(refreshed.AccessToken);
        Assert.DoesNotContain("transfers:write", scopes);
        Assert.Contains("transfers:read", scopes);
    }

    [Fact]
    public async Task Deactivated_user_cannot_refresh()
    {
        var email = await NewUserEmail("operator");
        var first = await OAuth.SignIn(email, GoodPassword);
        await Db(async db =>
        {
            await db.Users.Where(u => u.Email == email).ExecuteUpdateAsync(s => s.SetProperty(u => u.IsActive, false));
            return 0;
        });

        var res = await OAuth.Refresh(OAuth.NewClient(), first.RefreshToken!);
        Assert.Equal(HttpStatusCode.BadRequest, res.StatusCode);
    }

    // ---- revocation ---------------------------------------------------------------------------------------

    [Fact]
    public async Task Revoked_refresh_token_can_no_longer_be_used()
    {
        var tokens = await OAuth.SignIn(ApiFactory.AdminEmail, ApiFactory.AdminPassword);
        var c = OAuth.NewClient();

        Assert.Equal(HttpStatusCode.OK, (await OAuth.Revoke(c, tokens.RefreshToken!)).StatusCode);
        Assert.Equal(HttpStatusCode.BadRequest, (await OAuth.Refresh(c, tokens.RefreshToken!)).StatusCode);
    }

    [Fact]
    public async Task Revoking_an_unknown_token_is_200_per_rfc7009()
    {
        Assert.Equal(HttpStatusCode.OK, (await OAuth.Revoke(OAuth.NewClient(), "not-a-real-token")).StatusCode);
    }
}
