using System.Net;
using Identity.Tests.Infrastructure;
using Microsoft.EntityFrameworkCore;

namespace Identity.Tests;

// Defaults under test: lock after 5 failures, first lock 30s, doubling per further failure.
// Login is the real form POST: 302 = success, 401 = failure (never says why), 429 = throttled.
public class LoginAndLockoutTests(PostgresFixture pg) : ApiTestBase(pg)
{
    private async Task Fail(string email, int times)
    {
        for (var i = 0; i < times; i++)
            Assert.Equal(HttpStatusCode.Unauthorized, (await Login(email, "wrong-password-123")).StatusCode);
    }

    private Task<(int Count, DateTimeOffset? Until)> State(string email) =>
        Db(async db =>
        {
            var u = await db.Users.AsNoTracking().SingleAsync(x => x.Email == email);
            return (u.FailedLoginCount, u.LockedUntil);
        });

    [Fact]
    public async Task Successful_login_redirects_and_sets_a_session_cookie()
    {
        var email = await NewUserEmail("operator");
        var res = await Login(email, GoodPassword);
        Assert.Equal(HttpStatusCode.Redirect, res.StatusCode);
        Assert.Contains(res.Headers.GetValues("Set-Cookie"), c => c.StartsWith("identity.session=") && c.Contains("httponly", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public async Task Wrong_password_and_unknown_user_are_indistinguishable()
    {
        var email = await NewUserEmail();
        var wrong = await Login(email, "wrong-password-123");
        var unknown = await Login("nobody@example.com", "wrong-password-123");

        Assert.Equal(HttpStatusCode.Unauthorized, wrong.StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, unknown.StatusCode);
        foreach (var body in new[] { await wrong.Content.ReadAsStringAsync(), await unknown.Content.ReadAsStringAsync() })
        {
            Assert.Contains("The email or password is incorrect.", body);
            Assert.DoesNotContain("locked", body, StringComparison.OrdinalIgnoreCase);
            Assert.DoesNotContain("exist", body, StringComparison.OrdinalIgnoreCase);
        }
    }

    [Fact]
    public async Task Email_match_is_case_insensitive()
    {
        var email = await NewUserEmail();
        Assert.Equal(HttpStatusCode.Redirect, (await Login(email.ToUpperInvariant(), GoodPassword)).StatusCode);
    }

    [Fact]
    public async Task Locks_after_threshold_and_rejects_even_the_correct_password()
    {
        var email = await NewUserEmail();
        await Fail(email, 4);
        Assert.Null((await State(email)).Until); // below threshold: not locked

        await Fail(email, 1);
        var (count, until) = await State(email);
        Assert.Equal(5, count);
        Assert.Equal(Clock.GetUtcNow().AddSeconds(30), until);

        Assert.Equal(HttpStatusCode.Unauthorized, (await Login(email, GoodPassword)).StatusCode);
    }

    [Fact]
    public async Task Attempts_during_a_lock_do_not_extend_it()
    {
        var email = await NewUserEmail();
        await Fail(email, 5);
        var before = await State(email);

        Clock.Advance(TimeSpan.FromSeconds(10));
        await Fail(email, 3);

        Assert.Equal(before, await State(email));
    }

    [Fact]
    public async Task Lock_releases_after_the_backoff_and_success_resets_the_counter()
    {
        var email = await NewUserEmail();
        await Fail(email, 5);

        Clock.Advance(TimeSpan.FromSeconds(29));
        Assert.Equal(HttpStatusCode.Unauthorized, (await Login(email, GoodPassword)).StatusCode);

        Clock.Advance(TimeSpan.FromSeconds(2));
        Assert.Equal(HttpStatusCode.Redirect, (await Login(email, GoodPassword)).StatusCode);
        Assert.Equal((0, (DateTimeOffset?)null), await State(email));
    }

    [Fact]
    public async Task Backoff_doubles_on_each_further_failure_and_is_capped()
    {
        var email = await NewUserEmail();
        await Fail(email, 5);                                   // 30s
        Clock.Advance(TimeSpan.FromSeconds(31));
        await Fail(email, 1);                                   // count 6 -> 60s
        Assert.Equal(Clock.GetUtcNow().AddSeconds(60), (await State(email)).Until);

        Clock.Advance(TimeSpan.FromSeconds(61));
        await Fail(email, 1);                                   // count 7 -> 120s
        Assert.Equal(Clock.GetUtcNow().AddSeconds(120), (await State(email)).Until);

        for (var i = 0; i < 12; i++)                            // push far past the cap
        {
            Clock.Advance(TimeSpan.FromHours(2));
            await Fail(email, 1);
        }
        Assert.Equal(Clock.GetUtcNow().AddSeconds(3600), (await State(email)).Until);
    }

    [Fact]
    public async Task Success_below_threshold_resets_the_failure_count()
    {
        var email = await NewUserEmail();
        await Fail(email, 4);
        Assert.Equal(HttpStatusCode.Redirect, (await Login(email, GoodPassword)).StatusCode);
        await Fail(email, 4);
        Assert.Null((await State(email)).Until); // would be locked if the first 4 still counted
    }

    [Fact]
    public async Task Parallel_failures_cannot_dodge_the_lockout()
    {
        var email = await NewUserEmail();
        await Task.WhenAll(Enumerable.Range(0, 5).Select(_ => Login(email, "wrong-password-123")));
        Assert.NotNull((await State(email)).Until);
    }

    [Fact]
    public async Task Inactive_user_cannot_log_in()
    {
        var email = await NewUserEmail();
        await Db(async db =>
        {
            await db.Users.Where(u => u.Email == email).ExecuteUpdateAsync(s => s.SetProperty(u => u.IsActive, false));
            return 0;
        });
        Assert.Equal(HttpStatusCode.Unauthorized, (await Login(email, GoodPassword)).StatusCode);
    }

    [Fact]
    public async Task Missing_fields_are_400()
    {
        Assert.Equal(HttpStatusCode.BadRequest, (await Login("", "x")).StatusCode);
    }

    [Fact]
    public async Task Post_without_antiforgery_token_is_rejected()
    {
        var res = await Client.PostAsync("/account/login", new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["email"] = ApiFactory.AdminEmail, ["password"] = ApiFactory.AdminPassword,
        }));
        Assert.Equal(HttpStatusCode.BadRequest, res.StatusCode);
    }

    [Fact]
    public async Task Return_url_must_be_a_local_path()
    {
        var c = OAuth.NewClient();
        var res = await OAuth.FormLogin(c, ApiFactory.AdminEmail, ApiFactory.AdminPassword, returnUrl: "https://evil.example/steal");
        Assert.Equal(HttpStatusCode.Redirect, res.StatusCode);
        Assert.Equal("/", res.Headers.Location!.OriginalString); // not evil.example
    }
}
