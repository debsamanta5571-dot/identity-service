using System.Net;
using System.Net.Http.Json;
using Identity.Tests.Infrastructure;
using Microsoft.EntityFrameworkCore;

namespace Identity.Tests;

public class UserEndpointTests(PostgresFixture pg) : ApiTestBase(pg)
{
    [Fact]
    public async Task Create_user_returns_201_and_never_exposes_the_hash()
    {
        var res = await CreateUser("Alice@Example.com", GoodPassword, "operator");

        Assert.Equal(HttpStatusCode.Created, res.StatusCode);
        var body = await res.Content.ReadAsStringAsync();
        Assert.DoesNotContain("argon2", body);
        Assert.DoesNotContain("password", body, StringComparison.OrdinalIgnoreCase);
        var json = await Json(res);
        Assert.Equal("alice@example.com", json.GetProperty("email").GetString()); // normalized
        Assert.Equal("operator", json.GetProperty("roles")[0].GetString());
    }

    [Fact]
    public async Task Stored_password_is_an_argon2id_hash_not_the_password()
    {
        var email = await NewUserEmail();
        var stored = await Db(db => db.Users.Where(u => u.Email == email).Select(u => u.PasswordHash).SingleAsync());
        Assert.StartsWith("$argon2id$", stored);
        Assert.DoesNotContain(GoodPassword, stored);
    }

    [Fact]
    public async Task Duplicate_email_is_409_case_insensitively()
    {
        await CreateUser("dup@example.com");
        var res = await CreateUser("DUP@example.com");
        AssertProblemJson(res, HttpStatusCode.Conflict);
    }

    [Theory]
    [InlineData("not-an-email", GoodPassword, "email")]
    [InlineData("ok@example.com", "short", "password")]
    public async Task Invalid_input_is_400_problem_json(string email, string password, string field)
    {
        var res = await CreateUser(email, password);
        AssertProblemJson(res, HttpStatusCode.BadRequest);
        Assert.True((await Json(res)).GetProperty("errors").TryGetProperty(field, out _));
    }

    [Fact]
    public async Task Unknown_role_is_400()
    {
        var res = await CreateUser("x@example.com", GoodPassword, "no-such-role");
        AssertProblemJson(res, HttpStatusCode.BadRequest);
    }

    [Fact]
    public async Task Get_user_returns_200_or_404()
    {
        var created = await Json(await CreateUser("get@example.com", GoodPassword, "auditor"));
        var ok = await Api.GetAsync($"/api/users/{created.GetProperty("id").GetGuid()}");
        Assert.Equal(HttpStatusCode.OK, ok.StatusCode);
        Assert.Equal("auditor", (await Json(ok)).GetProperty("roles")[0].GetString());

        AssertProblemJson(await Api.GetAsync($"/api/users/{Guid.NewGuid()}"), HttpStatusCode.NotFound);
    }

    [Fact]
    public async Task Put_roles_replaces_the_role_set_and_changes_scopes()
    {
        var email = await NewUserEmail("auditor");
        var id = await Db(db => db.Users.Where(u => u.Email == email).Select(u => u.Id).SingleAsync());

        var res = await Api.PutAsJsonAsync($"/api/users/{id}/roles", new { roles = new[] { "operator" } });
        Assert.Equal(HttpStatusCode.OK, res.StatusCode);
        Assert.Equal(["operator"], (await Json(res)).GetProperty("roles").EnumerateArray().Select(x => x.GetString()));

        var scopes = ScopesOf((await OAuth.SignIn(email, GoodPassword)).AccessToken);
        Assert.Contains("transfers:write", scopes);
        Assert.DoesNotContain("audit:read", scopes);
    }

    [Fact]
    public async Task Put_roles_404_for_missing_user_and_400_for_unknown_role()
    {
        AssertProblemJson(await Api.PutAsJsonAsync($"/api/users/{Guid.NewGuid()}/roles", new { roles = new[] { "admin" } }), HttpStatusCode.NotFound);

        var email = await NewUserEmail();
        var id = await Db(db => db.Users.Where(u => u.Email == email).Select(u => u.Id).SingleAsync());
        AssertProblemJson(await Api.PutAsJsonAsync($"/api/users/{id}/roles", new { roles = new[] { "nope" } }), HttpStatusCode.BadRequest);
    }

    [Fact]
    public async Task Admin_endpoints_reject_missing_and_insufficient_tokens()
    {
        Assert.Equal(HttpStatusCode.Unauthorized, (await Client.GetAsync("/api/roles")).StatusCode);

        var email = await NewUserEmail("operator"); // no users:admin
        var operatorToken = (await OAuth.SignIn(email, GoodPassword)).AccessToken;
        using var operatorClient = BearerClient(operatorToken);
        Assert.Equal(HttpStatusCode.Forbidden, (await operatorClient.GetAsync("/api/roles")).StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden, (await operatorClient.PostAsJsonAsync("/api/users", new { email = "x@example.com", password = GoodPassword, displayName = "x" })).StatusCode);
    }

    [Fact]
    public async Task Responses_carry_security_headers()
    {
        var res = await Client.GetAsync("/api/scopes"); // even 401 responses carry the headers
        Assert.Equal("nosniff", res.Headers.GetValues("X-Content-Type-Options").Single());
        Assert.Equal("DENY", res.Headers.GetValues("X-Frame-Options").Single());
        Assert.Contains("frame-ancestors 'none'", res.Headers.GetValues("Content-Security-Policy").Single());
        Assert.Equal("no-store", res.Headers.CacheControl?.ToString());
    }
}
