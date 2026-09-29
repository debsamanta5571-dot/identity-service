using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Identity.Api.Security;
using Identity.Tests.Infrastructure;
using Microsoft.EntityFrameworkCore;

namespace Identity.Tests;

public class MfaTests(PostgresFixture pg) : ApiTestBase(pg)
{
    private string CurrentCode(string base32Secret, int stepOffset = 0) =>
        Totp.CodeFor(Totp.Base32Decode(base32Secret), Totp.StepAt(Clock.GetUtcNow()) + stepOffset);

    /// <summary>Creates a user, enrolls and confirms MFA. Returns the email, the secret and the recovery codes.</summary>
    private async Task<(string Email, string Secret, string[] Recovery)> UserWithMfa()
    {
        var email = await NewUserEmail("operator");
        using var me = BearerClient((await OAuth.SignIn(email, GoodPassword)).AccessToken);

        var enroll = await Json(await me.PostAsync("/api/mfa/enroll", null));
        var secret = enroll.GetProperty("secret").GetString()!;

        var confirm = await me.PostAsJsonAsync("/api/mfa/confirm", new { code = CurrentCode(secret) });
        Assert.Equal(HttpStatusCode.OK, confirm.StatusCode);
        var recovery = (await Json(confirm)).GetProperty("recoveryCodes").EnumerateArray().Select(x => x.GetString()!).ToArray();

        Clock.Advance(TimeSpan.FromSeconds(Totp.StepSeconds)); // the enrollment code's step is used up; move to a fresh one
        return (email, secret, recovery);
    }

    // ---- enrollment ---------------------------------------------------------------------------------------

    [Fact]
    public async Task Enroll_returns_secret_otpauth_uri_and_a_png_qr_code()
    {
        var email = await NewUserEmail();
        using var me = BearerClient((await OAuth.SignIn(email, GoodPassword)).AccessToken);

        var res = await me.PostAsync("/api/mfa/enroll", null);
        Assert.Equal(HttpStatusCode.OK, res.StatusCode);
        var json = await Json(res);

        var secret = json.GetProperty("secret").GetString()!;
        Assert.Equal(32, secret.Length); // 20 bytes -> 32 base32 chars
        Assert.StartsWith("otpauth://totp/", json.GetProperty("otpauthUri").GetString());
        Assert.Contains("secret=" + secret, json.GetProperty("otpauthUri").GetString());

        var qr = json.GetProperty("qrCodePng").GetString()!;
        Assert.StartsWith("data:image/png;base64,", qr);
        var png = Convert.FromBase64String(qr["data:image/png;base64,".Length..]);
        Assert.Equal(new byte[] { 0x89, 0x50, 0x4E, 0x47 }, png[..4]); // PNG signature
    }

    [Fact]
    public async Task Secret_is_encrypted_at_rest_and_mfa_is_off_until_confirmed()
    {
        var email = await NewUserEmail();
        using var me = BearerClient((await OAuth.SignIn(email, GoodPassword)).AccessToken);
        var secret = Totp.Base32Decode((await Json(await me.PostAsync("/api/mfa/enroll", null))).GetProperty("secret").GetString()!);

        var (enabled, stored) = await Db(async db =>
        {
            var u = await db.Users.AsNoTracking().SingleAsync(x => x.Email == email);
            return (u.MfaEnabled, u.MfaSecret);
        });
        Assert.False(enabled);
        Assert.NotNull(stored);
        Assert.False(stored.AsSpan().IndexOf(secret) >= 0); // ciphertext, not the raw secret

        // and a login still needs no code, since enrollment was not confirmed
        Assert.Equal(HttpStatusCode.Redirect, (await Login(email, GoodPassword)).StatusCode);
    }

    [Fact]
    public async Task Confirm_with_a_wrong_code_is_rejected_and_mfa_stays_off()
    {
        var email = await NewUserEmail();
        using var me = BearerClient((await OAuth.SignIn(email, GoodPassword)).AccessToken);
        await me.PostAsync("/api/mfa/enroll", null);

        AssertProblemJson(await me.PostAsJsonAsync("/api/mfa/confirm", new { code = "000000" }), HttpStatusCode.BadRequest);
        Assert.False(await Db(db => db.Users.Where(u => u.Email == email).Select(u => u.MfaEnabled).SingleAsync()));
    }

    [Fact]
    public async Task Confirm_returns_ten_recovery_codes_stored_only_as_hashes()
    {
        var (email, _, recovery) = await UserWithMfa();
        Assert.Equal(10, recovery.Length);
        Assert.Equal(10, recovery.Distinct().Count());

        var hashes = await Db(db => db.RecoveryCodes.Where(r => db.Users.Any(u => u.Id == r.UserId && u.Email == email)).Select(r => r.CodeHash).ToListAsync());
        Assert.Equal(10, hashes.Count);
        Assert.DoesNotContain(hashes, h => recovery.Any(c => h.Contains(c.Replace("-", ""), StringComparison.OrdinalIgnoreCase)));
    }

    [Fact]
    public async Task Enrolling_again_when_mfa_is_enabled_is_409()
    {
        var (email, secret, _) = await UserWithMfa();
        using var me = BearerClient((await OAuth.SignIn(email, GoodPassword, totp: CurrentCode(secret))).AccessToken);
        AssertProblemJson(await me.PostAsync("/api/mfa/enroll", null), HttpStatusCode.Conflict);
    }

    [Fact]
    public async Task Mfa_endpoints_require_a_token()
    {
        Assert.Equal(HttpStatusCode.Unauthorized, (await Client.PostAsync("/api/mfa/enroll", null)).StatusCode);
    }

    // ---- login with a second factor -----------------------------------------------------------------------

    [Fact]
    public async Task Login_without_a_code_asks_for_one_and_does_not_sign_in()
    {
        var (email, _, _) = await UserWithMfa();
        var res = await Login(email, GoodPassword);

        Assert.Equal(HttpStatusCode.OK, res.StatusCode); // the form again, not a redirect
        Assert.Contains("authenticator", await res.Content.ReadAsStringAsync());
        Assert.False(res.Headers.Contains("Set-Cookie") && res.Headers.GetValues("Set-Cookie").Any(c => c.StartsWith("identity.session=")));
    }

    [Fact]
    public async Task Valid_totp_code_signs_in_and_full_oauth_flow_works()
    {
        var (email, secret, _) = await UserWithMfa();
        var tokens = await OAuth.SignIn(email, GoodPassword, totp: CurrentCode(secret));
        Assert.Contains("transfers:write", ScopesOf(tokens.AccessToken));
    }

    [Fact]
    public async Task A_replayed_totp_code_is_rejected()
    {
        var (email, secret, _) = await UserWithMfa();
        var code = CurrentCode(secret);

        Assert.Equal(HttpStatusCode.Redirect, (await Login(email, GoodPassword, code)).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await Login(email, GoodPassword, code)).StatusCode); // same code, same step

        // still inside the drift window, but that step was already consumed
        Clock.Advance(TimeSpan.FromSeconds(Totp.StepSeconds));
        Assert.Equal(HttpStatusCode.Unauthorized, (await Login(email, GoodPassword, code)).StatusCode);

        // a genuinely new code works
        Assert.Equal(HttpStatusCode.Redirect, (await Login(email, GoodPassword, CurrentCode(secret))).StatusCode);
    }

    [Fact]
    public async Task Wrong_password_with_a_valid_code_fails()
    {
        var (email, secret, _) = await UserWithMfa();
        Assert.Equal(HttpStatusCode.Unauthorized, (await Login(email, "wrong-password-123", CurrentCode(secret))).StatusCode);
    }

    [Fact]
    public async Task Wrong_codes_count_toward_lockout_so_codes_cannot_be_brute_forced()
    {
        var (email, secret, _) = await UserWithMfa();
        for (var i = 0; i < 5; i++)
            Assert.Equal(HttpStatusCode.Unauthorized, (await Login(email, GoodPassword, "000000")).StatusCode);

        Assert.NotNull(await Db(db => db.Users.Where(u => u.Email == email).Select(u => u.LockedUntil).SingleAsync()));
        // locked: even the right password and a right code are refused
        Assert.Equal(HttpStatusCode.Unauthorized, (await Login(email, GoodPassword, CurrentCode(secret))).StatusCode);
    }

    [Fact]
    public async Task Asking_for_a_code_does_not_reset_or_increment_the_failure_count()
    {
        var (email, _, _) = await UserWithMfa();
        await Login(email, "wrong-password-123");                 // count 1
        await Login(email, GoodPassword);                         // right password, code requested
        Assert.Equal(1, await Db(db => db.Users.Where(u => u.Email == email).Select(u => u.FailedLoginCount).SingleAsync()));
    }

    // ---- recovery codes -----------------------------------------------------------------------------------

    [Fact]
    public async Task Recovery_code_signs_in_exactly_once()
    {
        var (email, _, recovery) = await UserWithMfa();

        Assert.Equal(HttpStatusCode.Redirect, (await Login(email, GoodPassword, recovery[0])).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await Login(email, GoodPassword, recovery[0])).StatusCode);
        Assert.Equal(HttpStatusCode.Redirect, (await Login(email, GoodPassword, recovery[1])).StatusCode); // others still work
    }

    [Fact]
    public async Task Recovery_code_is_accepted_case_and_hyphen_insensitively()
    {
        var (email, _, recovery) = await UserWithMfa();
        Assert.Equal(HttpStatusCode.Redirect, (await Login(email, GoodPassword, recovery[2].Replace("-", "").ToLowerInvariant())).StatusCode);
    }

    [Fact]
    public async Task Concurrent_use_of_one_recovery_code_succeeds_at_most_once()
    {
        var (email, _, recovery) = await UserWithMfa();
        var results = await Task.WhenAll(Enumerable.Range(0, 4).Select(_ => Login(email, GoodPassword, recovery[3])));
        Assert.Equal(1, results.Count(r => r.StatusCode == HttpStatusCode.Redirect));
    }

    // ---- disabling ----------------------------------------------------------------------------------------

    [Fact]
    public async Task Disable_needs_a_valid_code_then_login_needs_none()
    {
        var (email, secret, _) = await UserWithMfa();
        using var me = BearerClient((await OAuth.SignIn(email, GoodPassword, totp: CurrentCode(secret))).AccessToken);
        Clock.Advance(TimeSpan.FromSeconds(Totp.StepSeconds));

        AssertProblemJson(await me.PostAsJsonAsync("/api/mfa/disable", new { code = "000000" }), HttpStatusCode.BadRequest);
        Assert.Equal(HttpStatusCode.NoContent, (await me.PostAsJsonAsync("/api/mfa/disable", new { code = CurrentCode(secret) })).StatusCode);

        Assert.Equal(HttpStatusCode.Redirect, (await Login(email, GoodPassword)).StatusCode);
        Assert.Empty(await Db(db => db.RecoveryCodes.Where(r => db.Users.Any(u => u.Id == r.UserId && u.Email == email)).ToListAsync()));
    }
}
