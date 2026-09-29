using System.Net;
using Identity.Tests.Infrastructure;

namespace Identity.Tests;

public class PerIpRateLimitTests(PostgresFixture pg)
    : ApiTestBase(pg, new() { ["Throttle:PerIpPermits"] = "3" })
{
    [Fact]
    public async Task Login_posts_beyond_the_per_ip_limit_get_429_with_retry_after()
    {
        // InitializeAsync already used the admin login once (1 of 3 permits).
        for (var i = 0; i < 2; i++)
            Assert.Equal(HttpStatusCode.Unauthorized, (await Login($"user{i}@example.com", "wrong-password-123")).StatusCode);

        var res = await Login("another@example.com", "wrong-password-123");
        Assert.Equal(HttpStatusCode.TooManyRequests, res.StatusCode);
        Assert.Equal("application/problem+json", res.Content.Headers.ContentType?.MediaType);
        Assert.True(res.Headers.Contains("Retry-After"));
    }
}

public class PerAccountRateLimitTests(PostgresFixture pg)
    : ApiTestBase(pg, new() { ["Throttle:PerAccountPermits"] = "3" })
{
    [Fact]
    public async Task Per_account_limit_applies_to_that_account_only()
    {
        for (var i = 0; i < 3; i++) await Login("victim@example.com", "wrong-password-123");

        var limited = await Login("victim@example.com", "wrong-password-123");
        Assert.Equal(HttpStatusCode.TooManyRequests, limited.StatusCode);
        Assert.True(limited.Headers.Contains("Retry-After"));

        // a different account from the same IP is unaffected
        Assert.Equal(HttpStatusCode.Unauthorized, (await Login("someone-else@example.com", "wrong-password-123")).StatusCode);
    }

    [Fact]
    public async Task Case_variants_share_one_account_bucket()
    {
        for (var i = 0; i < 3; i++) await Login("Victim@Example.com", "wrong-password-123");
        Assert.Equal(HttpStatusCode.TooManyRequests, (await Login("victim@example.COM", "wrong-password-123")).StatusCode);
    }
}
