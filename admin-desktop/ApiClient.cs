using System.Net.Http.Json;
using System.Text.Json;

namespace IdentityAdmin;

internal sealed record UserRow(
    Guid Id, string Email, string DisplayName, bool IsActive, string[] Roles, DateTimeOffset CreatedAt,
    bool MfaEnabled, DateTimeOffset? LockedUntil);

internal sealed record RoleRow(Guid Id, string Name, string Description, string[] Scopes);

internal sealed record Paged<T>(List<T> Items, int Page, int PageSize, int Total);

/// <summary>An API error, already reduced from RFC 7807 problem+json to one readable sentence.</summary>
internal sealed class ApiException(string message) : Exception(message);

/// <summary>The identity service's admin API (needs the users:admin scope). Every call carries a fresh bearer token.</summary>
internal sealed class ApiClient(AuthClient auth)
{
    private readonly HttpClient _http = new();

    public Task<List<RoleRow>> RolesAsync(CancellationToken ct = default) =>
        SendAsync<List<RoleRow>>(HttpMethod.Get, "/api/roles", null, ct);

    public Task<Paged<UserRow>> UsersAsync(string? search, int page, int pageSize, CancellationToken ct = default) =>
        SendAsync<Paged<UserRow>>(HttpMethod.Get,
            $"/api/users?page={page}&pageSize={pageSize}" + (string.IsNullOrWhiteSpace(search) ? "" : $"&search={Uri.EscapeDataString(search.Trim())}"), null, ct);

    public Task<UserRow> CreateUserAsync(string email, string displayName, string password, IEnumerable<string> roles, CancellationToken ct = default) =>
        SendAsync<UserRow>(HttpMethod.Post, "/api/users", new { email, displayName, password, roles = roles.ToArray() }, ct);

    public Task<UserRow> SetActiveAsync(Guid id, bool isActive, CancellationToken ct = default) =>
        SendAsync<UserRow>(HttpMethod.Put, $"/api/users/{id}/status", new { isActive }, ct);

    private async Task<T> SendAsync<T>(HttpMethod method, string path, object? body, CancellationToken ct)
    {
        using var request = new HttpRequestMessage(method, auth.Server + path);
        request.Headers.Authorization = AuthClient.Bearer(await auth.GetTokenAsync(ct));
        if (body is not null) request.Content = JsonContent.Create(body);

        using var response = await _http.SendAsync(request, ct);
        if (response.IsSuccessStatusCode) return (await response.Content.ReadFromJsonAsync<T>(ct))!;
        throw new ApiException(await ProblemAsync(response, ct));
    }

    private static async Task<string> ProblemAsync(HttpResponseMessage response, CancellationToken ct)
    {
        try
        {
            using var doc = JsonDocument.Parse(await response.Content.ReadAsStringAsync(ct));
            var root = doc.RootElement;
            if (root.TryGetProperty("errors", out var errors))
                return string.Join(" ", errors.EnumerateObject().SelectMany(p => p.Value.EnumerateArray().Select(v => v.GetString())));
            if (root.TryGetProperty("detail", out var detail) && detail.GetString() is { Length: > 0 } d) return d;
            if (root.TryGetProperty("title", out var title)) return title.GetString() ?? "Request failed.";
        }
        catch (JsonException) { /* not a problem document */ }

        return response.StatusCode switch
        {
            System.Net.HttpStatusCode.Forbidden => "This account is not allowed to do that (it needs the users:admin scope).",
            System.Net.HttpStatusCode.Unauthorized => "Not signed in.",
            _ => $"Request failed ({(int)response.StatusCode}).",
        };
    }
}
