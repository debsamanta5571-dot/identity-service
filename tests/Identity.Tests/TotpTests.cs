using System.Text;
using Identity.Api.Security;
using Microsoft.Extensions.Configuration;

namespace Identity.Tests;

public class TotpTests
{
    private static readonly byte[] RfcSecret = Encoding.ASCII.GetBytes("12345678901234567890"); // RFC 6238 appendix B

    // RFC 6238 SHA-1 test vectors (published as 8 digits; the 6-digit code is the last 6).
    [Theory]
    [InlineData(59L, "287082")]
    [InlineData(1111111109L, "081804")]
    [InlineData(1111111111L, "050471")]
    [InlineData(1234567890L, "005924")]
    [InlineData(2000000000L, "279037")]
    [InlineData(20000000000L, "353130")]
    public void Matches_the_rfc6238_test_vectors(long unixSeconds, string expected)
    {
        var step = Totp.StepAt(DateTimeOffset.FromUnixTimeSeconds(unixSeconds));
        Assert.Equal(expected, Totp.CodeFor(RfcSecret, step));
    }

    [Theory] // RFC 4648 test vectors
    [InlineData("", "")]
    [InlineData("f", "MY")]
    [InlineData("fo", "MZXQ")]
    [InlineData("foo", "MZXW6")]
    [InlineData("foob", "MZXW6YQ")]
    [InlineData("fooba", "MZXW6YTB")]
    [InlineData("foobar", "MZXW6YTBOI")]
    public void Base32_matches_rfc4648_and_round_trips(string text, string encoded)
    {
        var bytes = Encoding.ASCII.GetBytes(text);
        Assert.Equal(encoded, Totp.Base32Encode(bytes));
        Assert.Equal(bytes, Totp.Base32Decode(encoded));
    }

    [Fact]
    public void Accepts_current_code_and_one_step_of_drift_either_way()
    {
        var now = DateTimeOffset.FromUnixTimeSeconds(1_700_000_000);
        var step = Totp.StepAt(now);
        Assert.Equal(step, Totp.Match(RfcSecret, Totp.CodeFor(RfcSecret, step), now, null));
        Assert.Equal(step - 1, Totp.Match(RfcSecret, Totp.CodeFor(RfcSecret, step - 1), now, null));
        Assert.Equal(step + 1, Totp.Match(RfcSecret, Totp.CodeFor(RfcSecret, step + 1), now, null));
        Assert.Null(Totp.Match(RfcSecret, Totp.CodeFor(RfcSecret, step + 2), now, null));
        Assert.Null(Totp.Match(RfcSecret, Totp.CodeFor(RfcSecret, step - 2), now, null));
    }

    [Fact]
    public void A_step_that_was_already_accepted_is_rejected_replay()
    {
        var now = DateTimeOffset.FromUnixTimeSeconds(1_700_000_000);
        var step = Totp.StepAt(now);
        var code = Totp.CodeFor(RfcSecret, step);

        Assert.NotNull(Totp.Match(RfcSecret, code, now, lastAcceptedStep: null));
        Assert.Null(Totp.Match(RfcSecret, code, now, lastAcceptedStep: step));         // same code again
        Assert.Null(Totp.Match(RfcSecret, code, now, lastAcceptedStep: step + 1));     // older than what was accepted
    }

    [Theory]
    [InlineData("")]
    [InlineData("12345")]
    [InlineData("1234567")]
    [InlineData("12345a")]
    [InlineData("１２３４５６")] // full-width digits are not digits here
    public void Malformed_codes_never_match(string code)
    {
        Assert.Null(Totp.Match(RfcSecret, code, DateTimeOffset.UtcNow, null));
    }

    [Fact]
    public void Provisioning_uri_has_the_fields_authenticator_apps_read()
    {
        var uri = Totp.ProvisioningUri("Identity Service", "a@b.example", "JBSWY3DPEHPK3PXP");
        Assert.StartsWith("otpauth://totp/Identity%20Service:a%40b.example?", uri);
        Assert.Contains("secret=JBSWY3DPEHPK3PXP", uri);
        Assert.Contains("digits=6", uri);
        Assert.Contains("period=30", uri);
    }
}

public class SecretProtectorTests
{
    private static SecretProtector With(byte[] key) =>
        new(new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?> { ["Mfa:EncryptionKey"] = Convert.ToBase64String(key) }).Build());

    private static byte[] Key(byte fill) => Enumerable.Repeat(fill, 32).Select(x => x).ToArray();

    [Fact]
    public void Round_trips_and_does_not_contain_the_plaintext()
    {
        var p = With(Key(1));
        var secret = Encoding.ASCII.GetBytes("12345678901234567890");
        var blob = p.Protect(secret);

        Assert.Equal(secret, p.Unprotect(blob));
        Assert.False(blob.AsSpan().IndexOf(secret) >= 0);
    }

    [Fact]
    public void Same_plaintext_encrypts_differently_each_time()
    {
        var p = With(Key(1));
        var secret = new byte[20];
        Assert.NotEqual(p.Protect(secret), p.Protect(secret));
    }

    [Fact]
    public void Tampering_or_a_wrong_key_is_detected()
    {
        var blob = With(Key(1)).Protect(new byte[20]);
        var tampered = (byte[])blob.Clone();
        tampered[^1] ^= 1;

        Assert.ThrowsAny<Exception>(() => With(Key(1)).Unprotect(tampered));
        Assert.ThrowsAny<Exception>(() => With(Key(2)).Unprotect(blob));
    }

    [Fact]
    public void Missing_or_short_key_fails_loudly()
    {
        var none = new SecretProtector(new ConfigurationBuilder().Build());
        Assert.Throws<InvalidOperationException>(() => none.Protect(new byte[20]));
        Assert.Throws<InvalidOperationException>(() => With(new byte[16]).Protect(new byte[20]));
    }
}
