using System.Threading.RateLimiting;
using Microsoft.Extensions.Options;

namespace Identity.Api.Security;

public sealed class ThrottleOptions
{
    public int WindowSeconds { get; set; } = 60;
    public int PerIpPermits { get; set; } = 30;
    public int PerAccountPermits { get; set; } = 10;
}

/// <summary>
/// Per-account limiter keyed by normalized email (including emails that don't exist, so it leaks nothing).
/// The per-IP limit is the built-in ASP.NET Core rate limiter middleware, see Program.cs.
/// In-memory: correct for one instance; several replicas would need a shared store.
/// </summary>
public sealed class AccountRateLimiter : IDisposable
{
    private readonly PartitionedRateLimiter<string> _limiter;

    public AccountRateLimiter(IOptions<ThrottleOptions> options)
    {
        var t = options.Value;
        _limiter = PartitionedRateLimiter.Create<string, string>(email =>
            RateLimitPartition.GetFixedWindowLimiter(email, _ => new FixedWindowRateLimiterOptions
            {
                PermitLimit = t.PerAccountPermits,
                Window = TimeSpan.FromSeconds(t.WindowSeconds),
                QueueLimit = 0,
            }));
    }

    public bool TryAcquire(string email, out TimeSpan retryAfter)
    {
        using var lease = _limiter.AttemptAcquire(email);
        retryAfter = TimeSpan.Zero;
        if (lease.IsAcquired) return true;
        lease.TryGetMetadata(MetadataName.RetryAfter, out retryAfter);
        return false;
    }

    public void Dispose() => _limiter.Dispose();
}
