using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using Identity.Api.Data;
using Microsoft.IdentityModel.JsonWebTokens;

namespace Identity.Tests.Infrastructure;

[Collection("db")]
public abstract class ApiTestBase : IAsyncLifetime, IDisposable
{
    public const string GoodPassword = "correct-horse-battery";

    protected PostgresFixture Pg { get; }
    protected ApiFactory Factory { get; }
    protected HttpClient Client { get; }              // anonymous
    protected HttpClient Api { get; private set; } = null!; // bearer token of the bootstrapped admin
    protected OAuthFlow OAuth { get; }
    protected TestClock Clock => Factory.Clock;

    protected ApiTestBase(PostgresFixture pg, Dictionary<string, string?>? overrides = null)
    {
        Pg = pg;
        Factory = new ApiFactory(pg.ConnectionString, overrides);
        Client = Factory.CreateClient();
        OAuth = new OAuthFlow(Factory);
    }

    public async Task InitializeAsync()
    {
        var tokens = await OAuth.SignIn(ApiFactory.AdminEmail, ApiFactory.AdminPassword);
        Api = Factory.CreateClient();
        Api.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", tokens.AccessToken);
    }

    public Task DisposeAsync() => Task.CompletedTask;

    protected HttpClient BearerClient(string accessToken)
    {
        var c = Factory.CreateClient();
        c.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
        return c;
    }

    protected Task<HttpResponseMessage> CreateUser(string email, string password = GoodPassword, params string[] roles) =>
        Api.PostAsJsonAsync("/api/users", new { email, password, displayName = "Test User", roles });

    /// <summary>Posts the login form (fresh cookie jar). 302 = success, 401 = failure, 429 = throttled.</summary>
    protected Task<HttpResponseMessage> Login(string email, string password, string? code = null) =>
        OAuth.FormLogin(OAuth.NewClient(), email, password, code);

    protected async Task<string> NewUserEmail(params string[] roles)
    {
        var email = $"{Guid.NewGuid():N}@example.com";
        Assert.Equal(HttpStatusCode.Created, (await CreateUser(email, GoodPassword, roles)).StatusCode);
        return email;
    }

    protected Task<T> Db<T>(Func<IdentityDbContext, Task<T>> action) => Factory.WithDbAsync(action);

    protected static async Task<JsonElement> Json(HttpResponseMessage r) =>
        (await r.Content.ReadFromJsonAsync<JsonElement>());

    protected static JsonWebToken Jwt(string token) => new(token);

    protected static string[] ScopesOf(string accessToken) =>
        Jwt(accessToken).GetClaim("scope").Value.Split(' ', StringSplitOptions.RemoveEmptyEntries);

    protected static void AssertProblemJson(HttpResponseMessage r, HttpStatusCode status)
    {
        Assert.Equal(status, r.StatusCode);
        Assert.Equal("application/problem+json", r.Content.Headers.ContentType?.MediaType);
    }

    public void Dispose()
    {
        Client.Dispose();
        Api?.Dispose();
        Factory.Dispose();
    }
}
