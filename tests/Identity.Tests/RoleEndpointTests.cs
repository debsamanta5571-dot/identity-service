using System.Net;
using System.Net.Http.Json;
using Identity.Tests.Infrastructure;

namespace Identity.Tests;

public class RoleEndpointTests(PostgresFixture pg) : ApiTestBase(pg)
{
    private static string[] Names(System.Text.Json.JsonElement arr, string prop = "name") =>
        arr.EnumerateArray().Select(x => x.GetProperty(prop).GetString()!).ToArray();

    [Fact]
    public async Task Scopes_are_seeded_and_granular()
    {
        var scopes = Names(await Json(await Api.GetAsync("/api/scopes")));
        Assert.Equal(["accounts:read", "accounts:write", "audit:read", "ledger:admin", "transfers:read", "transfers:write", "users:admin"], scopes);
    }

    [Fact]
    public async Task Seeded_roles_map_to_the_expected_scopes()
    {
        var roles = await Json(await Api.GetAsync("/api/roles"));
        var byName = roles.EnumerateArray().ToDictionary(
            r => r.GetProperty("name").GetString()!,
            r => r.GetProperty("scopes").EnumerateArray().Select(s => s.GetString()!).ToArray());

        Assert.Equal(7, byName["admin"].Length);
        Assert.Contains("ledger:admin", byName["admin"]);
        Assert.Contains("transfers:write", byName["operator"]);
        Assert.DoesNotContain("users:admin", byName["operator"]);
        // Only admins may act on other people's ledger accounts.
        Assert.DoesNotContain("ledger:admin", byName["operator"]);
        Assert.DoesNotContain("ledger:admin", byName["auditor"]);
        Assert.DoesNotContain("transfers:write", byName["auditor"]); // read and write are separate scopes
        Assert.Contains("transfers:read", byName["auditor"]);
    }

    [Fact]
    public async Task Create_role_201_then_listed_with_its_scopes()
    {
        var res = await Api.PostAsJsonAsync("/api/roles", new { name = "read-only", description = "d", scopes = new[] { "accounts:read" } });
        Assert.Equal(HttpStatusCode.Created, res.StatusCode);

        var roles = await Json(await Api.GetAsync("/api/roles"));
        Assert.Contains("read-only", Names(roles));
    }

    [Fact]
    public async Task Create_role_rejects_bad_name_unknown_scope_and_duplicates()
    {
        AssertProblemJson(await Api.PostAsJsonAsync("/api/roles", new { name = "Bad Name!", scopes = Array.Empty<string>() }), HttpStatusCode.BadRequest);
        AssertProblemJson(await Api.PostAsJsonAsync("/api/roles", new { name = "ok-name", scopes = new[] { "nope:nope" } }), HttpStatusCode.BadRequest);
        AssertProblemJson(await Api.PostAsJsonAsync("/api/roles", new { name = "admin", scopes = Array.Empty<string>() }), HttpStatusCode.Conflict);
    }
}
