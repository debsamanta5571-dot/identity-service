using System.Net;
using System.Net.Http.Headers;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace IdentityAdmin;

/// <summary>
/// Signs the administrator in with the authorization code flow + PKCE, as a public client (RFC 8252, native apps).
/// The password is typed into the identity service's own login page in the browser (so MFA and lockout apply), never
/// into this program. The browser then redirects to a loopback address this program is listening on.
/// No crypto is implemented here: SHA-256 and randomness come from the platform.
/// </summary>
internal sealed class AuthClient
{
    public const string ClientId = "admin-desktop";
    public const int LoopbackPort = 53682;
    public static readonly string RedirectUri = $"http://127.0.0.1:{LoopbackPort}/callback";
    private const string Scope = "openid offline_access users:admin";
    private static readonly TimeSpan Skew = TimeSpan.FromSeconds(30);

    private readonly HttpClient _http = new();
    private readonly SemaphoreSlim _gate = new(1, 1);
    private readonly Action<string> _openBrowser;
    private string? _accessToken, _refreshToken;
    private DateTimeOffset _expiresAt;

    public string Server { get; }
    public string? Email { get; private set; }

    public AuthClient(string server, Action<string> openBrowser)
    {
        Server = server.TrimEnd('/');
        _openBrowser = openBrowser;
    }

    /// <summary>A valid access token: reuses the current one, else refreshes, else signs in again.</summary>
    public async Task<string> GetTokenAsync(CancellationToken ct = default)
    {
        await _gate.WaitAsync(ct); // one sign-in/refresh at a time
        try
        {
            if (_accessToken is not null && DateTimeOffset.UtcNow < _expiresAt - Skew) return _accessToken;
            if (_refreshToken is not null && await TryRefreshAsync(ct)) return _accessToken!;
            await SignInCoreAsync(ct);
            return _accessToken!;
        }
        finally { _gate.Release(); }
    }

    /// <summary>An explicit sign-in (the button): always goes through the browser, ignoring any current token.</summary>
    public async Task SignInAsync(CancellationToken ct = default)
    {
        await _gate.WaitAsync(ct);
        try { await SignInCoreAsync(ct); }
        finally { _gate.Release(); }
    }

    private async Task SignInCoreAsync(CancellationToken ct)
    {
        var verifier = Base64Url(RandomNumberGenerator.GetBytes(48));
        var challenge = Base64Url(SHA256.HashData(Encoding.ASCII.GetBytes(verifier)));
        var state = Base64Url(RandomNumberGenerator.GetBytes(16));

        var url = $"{Server}/connect/authorize?client_id={ClientId}&response_type=code"
                  + $"&redirect_uri={Uri.EscapeDataString(RedirectUri)}&scope={Uri.EscapeDataString(Scope)}"
                  + $"&state={state}&code_challenge={challenge}&code_challenge_method=S256";

        var listener = new TcpListener(IPAddress.Loopback, LoopbackPort);
        listener.Start();
        try
        {
            _openBrowser(url);
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
            timeout.CancelAfter(TimeSpan.FromMinutes(3));
            var query = await WaitForCallbackAsync(listener, timeout.Token);

            if (query.TryGetValue("error", out var error))
                throw new InvalidOperationException($"Sign-in failed: {query.GetValueOrDefault("error_description", error)}");
            if (query.GetValueOrDefault("state") != state) throw new InvalidOperationException("Sign-in failed: state mismatch."); // CSRF check
            var code = query.GetValueOrDefault("code") ?? throw new InvalidOperationException("Sign-in failed: no code returned.");

            await TokenRequestAsync(new()
            {
                ["grant_type"] = "authorization_code",
                ["code"] = code,
                ["redirect_uri"] = RedirectUri,
                ["code_verifier"] = verifier,
            }, ct);
        }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested)
        {
            throw new TimeoutException("Sign-in was not completed within 3 minutes.");
        }
        finally { listener.Stop(); }
    }

    /// <summary>Accepts connections until the browser requests /callback (it may also ask for /favicon.ico).</summary>
    private static async Task<Dictionary<string, string>> WaitForCallbackAsync(TcpListener listener, CancellationToken ct)
    {
        while (true)
        {
            using var client = await listener.AcceptTcpClientAsync(ct);
            using var stream = client.GetStream();
            var buffer = new byte[8192];
            var read = await stream.ReadAsync(buffer, ct);
            var requestLine = Encoding.ASCII.GetString(buffer, 0, read).Split("\r\n", 2)[0]; // GET /callback?code=..&state=.. HTTP/1.1
            var parts = requestLine.Split(' ');
            var target = parts.Length >= 2 ? parts[1] : "/";

            var isCallback = target.StartsWith("/callback", StringComparison.Ordinal);
            var body = isCallback
                ? "<!doctype html><meta charset=utf-8><title>Signed in</title><body style=\"font:16px system-ui;margin:3rem\"><h2>Signed in</h2><p>You can close this tab and return to Identity Admin.</p>"
                : "";
            var response = Encoding.UTF8.GetBytes(
                $"HTTP/1.1 {(isCallback ? "200 OK" : "404 Not Found")}\r\nContent-Type: text/html; charset=utf-8\r\n" +
                $"Content-Length: {Encoding.UTF8.GetByteCount(body)}\r\nConnection: close\r\nCache-Control: no-store\r\n\r\n{body}");
            await stream.WriteAsync(response, ct);

            if (!isCallback) continue;
            var q = target.IndexOf('?');
            return q < 0 ? [] : ParseQuery(target[(q + 1)..]);
        }
    }

    private static Dictionary<string, string> ParseQuery(string query) =>
        query.Split('&', StringSplitOptions.RemoveEmptyEntries)
            .Select(p => p.Split('=', 2))
            .ToDictionary(p => Uri.UnescapeDataString(p[0]), p => p.Length > 1 ? Uri.UnescapeDataString(p[1].Replace('+', ' ')) : "");

    private async Task<bool> TryRefreshAsync(CancellationToken ct)
    {
        try
        {
            await TokenRequestAsync(new() { ["grant_type"] = "refresh_token", ["refresh_token"] = _refreshToken! }, ct);
            return true;
        }
        catch (HttpRequestException) { return false; } // revoked or expired: fall back to a fresh sign-in
    }

    private async Task TokenRequestAsync(Dictionary<string, string> form, CancellationToken ct)
    {
        form["client_id"] = ClientId;
        using var res = await _http.PostAsync($"{Server}/connect/token", new FormUrlEncodedContent(form), ct);
        var json = await res.Content.ReadAsStringAsync(ct);
        if (!res.IsSuccessStatusCode) throw new HttpRequestException($"Token request failed ({(int)res.StatusCode}): {json}");

        using var doc = JsonDocument.Parse(json);
        var root = doc.RootElement;
        _accessToken = root.GetProperty("access_token").GetString();
        _refreshToken = root.TryGetProperty("refresh_token", out var rt) ? rt.GetString() : _refreshToken;
        _expiresAt = DateTimeOffset.UtcNow.AddSeconds(root.GetProperty("expires_in").GetInt32());
        if (root.TryGetProperty("id_token", out var id)) Email = ReadClaim(id.GetString()!, "email") ?? Email;
    }

    // The ID token came straight from our token endpoint over the direct connection, so its claims are only read here.
    private static string? ReadClaim(string jwt, string claim)
    {
        var payload = jwt.Split('.')[1].Replace('-', '+').Replace('_', '/');
        payload = payload.PadRight((payload.Length + 3) / 4 * 4, '=');
        using var doc = JsonDocument.Parse(Convert.FromBase64String(payload));
        return doc.RootElement.TryGetProperty(claim, out var v) ? v.GetString() : null;
    }

    private static string Base64Url(byte[] bytes) =>
        Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    public static AuthenticationHeaderValue Bearer(string token) => new("Bearer", token);
}
