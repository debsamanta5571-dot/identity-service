using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Identity.Tests.Infrastructure;
using Microsoft.EntityFrameworkCore;

namespace Identity.Tests;

/// <summary>The endpoints the Angular admin console uses: user list and status, sessions.</summary>
public class AdminApiTests(PostgresFixture pg) : ApiTestBase(pg)
{
    private Task<Guid> UserId(string email) => Db(db => db.Users.Where(u => u.Email == email).Select(u => u.Id).SingleAsync());

    // ---- users ----------------------------------------------------------------------------------------------

    [Fact]
    public async Task User_list_is_paged_and_searchable()
    {
        foreach (var n in new[] { "alpha", "beta", "gamma" })
            await CreateUser($"{n}@list.example");

        var all = await Json(await Api.GetAsync("/api/users?pageSize=2&page=1"));
        Assert.Equal(2, all.GetProperty("items").GetArrayLength());
        Assert.True(all.GetProperty("total").GetInt32() >= 4); // 3 + bootstrap admin

        var found = await Json(await Api.GetAsync("/api/users?search=BETA"));
        Assert.Equal(1, found.GetProperty("total").GetInt32());
        Assert.Equal("beta@list.example", found.GetProperty("items")[0].GetProperty("email").GetString());

        var wildcardIsLiteral = await Json(await Api.GetAsync("/api/users?search=%25")); // "%" must not match everything
        Assert.Equal(0, wildcardIsLiteral.GetProperty("total").GetInt32());
    }

    [Fact]
    public async Task User_list_exposes_mfa_and_lock_state_but_no_secrets()
    {
        var raw = await Api.GetStringAsync("/api/users");
        Assert.Contains("mfaEnabled", raw);
        Assert.Contains("lockedUntil", raw);
        Assert.DoesNotContain("argon2", raw);
        Assert.DoesNotContain("passwordHash", raw, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("mfaSecret", raw, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task Bad_paging_on_user_list_is_400()
    {
        AssertProblemJson(await Api.GetAsync("/api/users?pageSize=1000"), HttpStatusCode.BadRequest);
    }

    [Fact]
    public async Task Deactivating_a_user_blocks_login_and_kills_their_sessions()
    {
        var email = await NewUserEmail("operator");
        var id = await UserId(email);
        var tokens = await OAuth.SignIn(email, GoodPassword);

        var res = await Api.PutAsJsonAsync($"/api/users/{id}/status", new { isActive = false });
        Assert.Equal(HttpStatusCode.OK, res.StatusCode);
        Assert.False((await Json(res)).GetProperty("isActive").GetBoolean());

        Assert.Equal(HttpStatusCode.Unauthorized, (await Login(email, GoodPassword)).StatusCode);
        Assert.Equal(HttpStatusCode.BadRequest, (await OAuth.Refresh(OAuth.NewClient(), tokens.RefreshToken!)).StatusCode);

        // reactivation works
        await Api.PutAsJsonAsync($"/api/users/{id}/status", new { isActive = true });
        Assert.Equal(HttpStatusCode.Redirect, (await Login(email, GoodPassword)).StatusCode);
    }

    [Fact]
    public async Task Admin_cannot_deactivate_themselves()
    {
        var adminId = await UserId(ApiFactory.AdminEmail);
        AssertProblemJson(await Api.PutAsJsonAsync($"/api/users/{adminId}/status", new { isActive = false }), HttpStatusCode.BadRequest);
    }

    [Fact]
    public async Task Status_change_validates_input_and_is_audited()
    {
        var email = await NewUserEmail();
        var id = await UserId(email);
        AssertProblemJson(await Api.PutAsJsonAsync($"/api/users/{id}/status", new { }), HttpStatusCode.BadRequest);
        AssertProblemJson(await Api.PutAsJsonAsync($"/api/users/{Guid.NewGuid()}/status", new { isActive = false }), HttpStatusCode.NotFound);

        await Api.PutAsJsonAsync($"/api/users/{id}/status", new { isActive = false });
        var audit = await Json(await Api.GetAsync($"/api/audit?eventType=user.status_changed&userId={id}"));
        Assert.Equal(1, audit.GetProperty("total").GetInt32());
    }

    // ---- sessions -------------------------------------------------------------------------------------------

    private async Task<JsonElement[]> Sessions(string query = "") =>
        (await Json(await Api.GetAsync("/api/sessions" + query))).EnumerateArray().ToArray();

    [Fact]
    public async Task Sessions_list_shows_active_logins_with_user_and_client()
    {
        var email = await NewUserEmail("operator");
        var id = await UserId(email);
        await OAuth.SignIn(email, GoodPassword);
        await OAuth.SignIn(email, GoodPassword); // second device

        var mine = await Sessions($"?userId={id}");
        Assert.Equal(2, mine.Length);
        Assert.All(mine, s =>
        {
            Assert.Equal(email, s.GetProperty("email").GetString());
            Assert.Equal(OAuthFlow.ClientId, s.GetProperty("clientId").GetString());
            Assert.True(s.GetProperty("expiresAt").GetDateTimeOffset() > DateTimeOffset.UtcNow);
        });
        Assert.Contains((await Sessions()), s => s.GetProperty("email").GetString() == ApiFactory.AdminEmail); // the admin's own session
    }

    [Fact]
    public async Task Refreshing_keeps_one_session_and_reuse_removes_it()
    {
        var email = await NewUserEmail("operator");
        var id = await UserId(email);
        var t = await OAuth.SignIn(email, GoodPassword);
        var c = OAuth.NewClient();

        var t2 = await OAuthFlow.ReadTokens(await OAuth.Refresh(c, t.RefreshToken!));
        Assert.Single(await Sessions($"?userId={id}"));   // rotation replaces the token, not the session

        await OAuth.Refresh(c, t.RefreshToken!);           // replay of the old token
        Assert.Empty(await Sessions($"?userId={id}"));
        _ = t2;
    }

    [Fact]
    public async Task Revoking_a_session_ends_it_and_is_audited()
    {
        var email = await NewUserEmail("operator");
        var id = await UserId(email);
        var tokens = await OAuth.SignIn(email, GoodPassword);
        var session = (await Sessions($"?userId={id}")).Single();

        var res = await Api.DeleteAsync($"/api/sessions/{session.GetProperty("id").GetGuid()}");
        Assert.Equal(HttpStatusCode.NoContent, res.StatusCode);

        Assert.Empty(await Sessions($"?userId={id}"));
        Assert.Equal(HttpStatusCode.BadRequest, (await OAuth.Refresh(OAuth.NewClient(), tokens.RefreshToken!)).StatusCode);
        var audit = await Json(await Api.GetAsync($"/api/audit?eventType=session.revoked&userId={id}"));
        Assert.Equal(1, audit.GetProperty("total").GetInt32());
    }

    [Fact]
    public async Task Revoking_an_unknown_session_is_404()
    {
        AssertProblemJson(await Api.DeleteAsync($"/api/sessions/{Guid.NewGuid()}"), HttpStatusCode.NotFound);
    }

    [Fact]
    public async Task Session_and_user_admin_endpoints_need_users_admin()
    {
        var email = await NewUserEmail("auditor");
        using var auditor = BearerClient((await OAuth.SignIn(email, GoodPassword)).AccessToken);
        Assert.Equal(HttpStatusCode.Forbidden, (await auditor.GetAsync("/api/sessions")).StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden, (await auditor.GetAsync("/api/users")).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await Client.GetAsync("/api/sessions")).StatusCode);
    }
}
