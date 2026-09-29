using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Identity.Tests.Infrastructure;
using Microsoft.EntityFrameworkCore;
using Npgsql;

namespace Identity.Tests;

public class AuditTests(PostgresFixture pg) : ApiTestBase(pg)
{
    private async Task<JsonElement> Audit(string query = "")
    {
        var res = await Api.GetAsync("/api/audit" + query);
        Assert.Equal(HttpStatusCode.OK, res.StatusCode);
        return await Json(res);
    }

    private static JsonElement[] Items(JsonElement page) => page.GetProperty("items").EnumerateArray().ToArray();

    private Task<Guid> UserId(string email) => Db(db => db.Users.Where(u => u.Email == email).Select(u => u.Id).SingleAsync());

    // ---- what gets recorded ---------------------------------------------------------------------------------

    [Fact]
    public async Task Login_success_and_failure_are_recorded_with_the_reason_kept_server_side()
    {
        var email = await NewUserEmail();
        var id = await UserId(email);
        await Login(email, "wrong-password-123");
        await Login(email, GoodPassword);

        var failure = Items(await Audit($"?eventType=login.failure&userId={id}")).Single();
        Assert.False(failure.GetProperty("success").GetBoolean());
        Assert.Equal("bad_password", failure.GetProperty("details").GetProperty("reason").GetString());

        var success = Items(await Audit($"?eventType=login.success&userId={id}")).Single();
        Assert.True(success.GetProperty("success").GetBoolean());
    }

    [Fact]
    public async Task Failed_login_for_an_unknown_email_is_recorded_without_a_user_id()
    {
        await Login("ghost@example.com", "wrong-password-123");
        var e = Items(await Audit("?eventType=login.failure")).First(x => x.GetProperty("details").GetProperty("email").GetString() == "ghost@example.com");
        Assert.Equal(JsonValueKind.Null, e.GetProperty("userId").ValueKind);
        Assert.Equal("unknown_user", e.GetProperty("details").GetProperty("reason").GetString());
    }

    [Fact]
    public async Task Audit_entries_never_contain_passwords_or_tokens()
    {
        var email = await NewUserEmail();
        var tokens = await OAuth.SignIn(email, GoodPassword);
        await Login(email, "wrong-password-123");

        var raw = (await Api.GetStringAsync("/api/audit?pageSize=100"));
        Assert.DoesNotContain(GoodPassword, raw);
        Assert.DoesNotContain("wrong-password-123", raw);
        Assert.DoesNotContain(tokens.AccessToken, raw);
        Assert.DoesNotContain(tokens.RefreshToken!, raw);
    }

    [Fact]
    public async Task Token_issue_is_recorded_for_code_exchange_and_refresh()
    {
        var email = await NewUserEmail("operator");
        var id = await UserId(email);
        var tokens = await OAuth.SignIn(email, GoodPassword);
        await OAuth.Refresh(OAuth.NewClient(), tokens.RefreshToken!);

        var issued = Items(await Audit($"?eventType=token.issued&userId={id}"));
        Assert.Equal(2, issued.Length);
        Assert.Equal(["authorization_code", "refresh_token"], issued.Select(e => e.GetProperty("details").GetProperty("grantType").GetString()!).Order());
        Assert.All(issued, e => Assert.Equal(OAuthFlow.ClientId, e.GetProperty("clientId").GetString()));
    }

    [Fact]
    public async Task Refresh_token_reuse_is_recorded_as_a_security_event()
    {
        var email = await NewUserEmail("operator");
        var id = await UserId(email);
        var tokens = await OAuth.SignIn(email, GoodPassword);
        var c = OAuth.NewClient();
        await OAuth.Refresh(c, tokens.RefreshToken!);
        await OAuth.Refresh(c, tokens.RefreshToken!); // replay

        var events = Items(await Audit($"?eventType=token.refresh_reuse_detected&userId={id}"));
        Assert.Single(events);
        Assert.False(events[0].GetProperty("success").GetBoolean());
    }

    [Fact]
    public async Task Revocation_is_recorded()
    {
        var tokens = await OAuth.SignIn(ApiFactory.AdminEmail, ApiFactory.AdminPassword);
        await OAuth.Revoke(OAuth.NewClient(), tokens.RefreshToken!);
        Assert.NotEmpty(Items(await Audit("?eventType=token.revoked")));
    }

    [Fact]
    public async Task Role_change_records_actor_target_and_before_after()
    {
        var email = await NewUserEmail("auditor");
        var id = await UserId(email);
        var adminId = await UserId(ApiFactory.AdminEmail);
        await Api.PutAsJsonAsync($"/api/users/{id}/roles", new { roles = new[] { "operator" } });

        var e = Items(await Audit($"?eventType=role.changed&userId={id}")).Single();
        Assert.Equal(adminId, e.GetProperty("actorId").GetGuid());
        Assert.Equal(["auditor"], e.GetProperty("details").GetProperty("before").EnumerateArray().Select(x => x.GetString()));
        Assert.Equal(["operator"], e.GetProperty("details").GetProperty("after").EnumerateArray().Select(x => x.GetString()));
    }

    [Fact]
    public async Task User_and_role_creation_are_recorded()
    {
        await NewUserEmail();
        await Api.PostAsJsonAsync("/api/roles", new { name = "temp-role", scopes = new[] { "accounts:read" } });
        Assert.NotEmpty(Items(await Audit("?eventType=user.created")));
        Assert.NotEmpty(Items(await Audit("?eventType=role.created")));
    }

    // ---- querying -----------------------------------------------------------------------------------------

    [Fact]
    public async Task Filters_by_wildcard_success_and_ip()
    {
        var email = await NewUserEmail();
        await Login(email, "wrong-password-123");
        await Login(email, GoodPassword);

        var logins = Items(await Audit("?eventType=login.*&pageSize=100"));
        Assert.All(logins, e => Assert.StartsWith("login.", e.GetProperty("eventType").GetString()));

        var failures = Items(await Audit("?eventType=login.*&success=false&pageSize=100"));
        Assert.NotEmpty(failures);
        Assert.All(failures, e => Assert.False(e.GetProperty("success").GetBoolean()));

        var noMatch = Items(await Audit("?ip=203.0.113.99"));
        Assert.Empty(noMatch);
    }

    [Fact]
    public async Task Filters_by_time_range()
    {
        await NewUserEmail();
        var future = Uri.EscapeDataString(DateTimeOffset.UtcNow.AddDays(1).ToString("o"));
        var past = Uri.EscapeDataString(DateTimeOffset.UtcNow.AddDays(-1).ToString("o"));

        Assert.Empty(Items(await Audit($"?from={future}")));
        Assert.NotEmpty(Items(await Audit($"?from={past}")));
        Assert.Empty(Items(await Audit($"?to={past}")));
    }

    [Fact]
    public async Task Paginates_newest_first_with_a_total()
    {
        for (var i = 0; i < 6; i++) await Login($"nobody{i}@example.com", "wrong-password-123");

        var p1 = await Audit("?eventType=login.failure&pageSize=4&page=1");
        var p2 = await Audit("?eventType=login.failure&pageSize=4&page=2");

        Assert.Equal(6, p1.GetProperty("total").GetInt32());
        Assert.Equal(4, Items(p1).Length);
        Assert.Equal(2, Items(p2).Length);
        Assert.Equal(4, p1.GetProperty("pageSize").GetInt32());

        var ids = Items(p1).Concat(Items(p2)).Select(e => e.GetProperty("id").GetInt64()).ToArray();
        Assert.Equal(ids.OrderByDescending(x => x), ids);   // newest first, stable across pages
        Assert.Equal(ids.Length, ids.Distinct().Count());   // no overlap between pages
    }

    [Theory]
    [InlineData("?page=0")]
    [InlineData("?pageSize=0")]
    [InlineData("?pageSize=101")]
    public async Task Bad_paging_is_400_problem_json(string query)
    {
        AssertProblemJson(await Api.GetAsync("/api/audit" + query), HttpStatusCode.BadRequest);
    }

    // ---- access control -----------------------------------------------------------------------------------

    [Fact]
    public async Task Audit_endpoint_needs_the_audit_read_scope()
    {
        Assert.Equal(HttpStatusCode.Unauthorized, (await Client.GetAsync("/api/audit")).StatusCode);

        var operatorEmail = await NewUserEmail("operator"); // no audit:read
        using var op = BearerClient((await OAuth.SignIn(operatorEmail, GoodPassword)).AccessToken);
        Assert.Equal(HttpStatusCode.Forbidden, (await op.GetAsync("/api/audit")).StatusCode);

        var auditorEmail = await NewUserEmail("auditor");
        using var auditor = BearerClient((await OAuth.SignIn(auditorEmail, GoodPassword)).AccessToken);
        Assert.Equal(HttpStatusCode.OK, (await auditor.GetAsync("/api/audit")).StatusCode);
    }

    // ---- append-only ---------------------------------------------------------------------------------------

    [Fact]
    public async Task No_write_verbs_exist_for_the_audit_log()
    {
        foreach (var m in new[] { HttpMethod.Put, HttpMethod.Patch, HttpMethod.Delete, HttpMethod.Post })
        {
            var res = await Api.SendAsync(new HttpRequestMessage(m, "/api/audit/1") { Content = JsonContent.Create(new { }) });
            Assert.True(res.StatusCode is HttpStatusCode.NotFound or HttpStatusCode.MethodNotAllowed, $"{m} returned {res.StatusCode}");
            var res2 = await Api.SendAsync(new HttpRequestMessage(m, "/api/audit") { Content = JsonContent.Create(new { }) });
            Assert.True(res2.StatusCode is HttpStatusCode.NotFound or HttpStatusCode.MethodNotAllowed, $"{m} returned {res2.StatusCode}");
        }
    }

    [Fact]
    public async Task Database_rejects_update_delete_and_truncate_even_via_raw_sql()
    {
        await NewUserEmail(); // ensures at least one row

        foreach (var sql in new[]
        {
            "UPDATE audit_log SET event_type = 'tampered'",
            "DELETE FROM audit_log",
            "TRUNCATE audit_log",
        })
        {
            var ex = await Assert.ThrowsAnyAsync<Exception>(() => Db(async db => await db.Database.ExecuteSqlRawAsync(sql)));
            var pg = Assert.IsType<PostgresException>(ex is DbUpdateException ? ex.InnerException : ex);
            Assert.Contains("append-only", pg.MessageText);
        }
        Assert.NotEmpty(Items(await Audit()));
    }

    [Fact]
    public async Task Ef_core_refuses_to_update_or_delete_audit_entries()
    {
        await NewUserEmail();
        await Db(async db =>
        {
            var row = await db.AuditLog.FirstAsync();
            row.EventType = "tampered";
            await Assert.ThrowsAsync<InvalidOperationException>(() => db.SaveChangesAsync());

            db.ChangeTracker.Clear();
            db.AuditLog.Remove(await db.AuditLog.FirstAsync());
            await Assert.ThrowsAsync<InvalidOperationException>(() => db.SaveChangesAsync());
            return 0;
        });
    }
}
