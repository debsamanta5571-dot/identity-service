using System.Net;
using Identity.Tests.Infrastructure;
using Microsoft.EntityFrameworkCore;

namespace Identity.Tests;

public class BootstrapTests(PostgresFixture pg) : ApiTestBase(pg)
{
    [Fact]
    public async Task First_admin_is_created_from_configuration_and_holds_the_admin_role()
    {
        var res = await Login(ApiFactory.AdminEmail, ApiFactory.AdminPassword);
        Assert.Equal(HttpStatusCode.Redirect, res.StatusCode);

        var roles = await Db(db => db.UserRoles.Where(ur => ur.User.Email == ApiFactory.AdminEmail).Select(ur => ur.Role.Name).ToListAsync());
        Assert.Equal(["admin"], roles);
    }

    [Fact]
    public async Task Bootstrap_only_runs_when_there_are_no_users()
    {
        Assert.Equal(1, await Db(db => db.Users.CountAsync()));
    }
}

public class MigrationTests(PostgresFixture pg) : ApiTestBase(pg)
{
    [Fact]
    public async Task Migrations_apply_cleanly_and_seed_reference_data()
    {
        var (roles, scopes, pending) = await Db(async db =>
            (await db.Roles.CountAsync(), await db.Scopes.CountAsync(), (await db.Database.GetPendingMigrationsAsync()).Count()));
        Assert.Equal((3, 7, 0), (roles, scopes, pending));
    }
}
