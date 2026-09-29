using OpenIddict.Abstractions;
using OpenIddict.Server;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace Identity.Api.Security;

/// <summary>
/// Refresh token reuse detection. Runs just before OpenIddict validates the token's database entry.
/// Refresh tokens rotate: using one marks it Redeemed and issues the next. If a Redeemed one shows up again,
/// either the client is buggy or the token was stolen, and we cannot tell which, so the whole family
/// (the authorization plus every token issued under it) is revoked and a security event is recorded.
/// </summary>
public sealed class RefreshReuseDetector(
    IOpenIddictTokenManager tokens,
    IOpenIddictAuthorizationManager authorizations,
    AuditService audit,
    ILogger<RefreshReuseDetector> log) : IOpenIddictServerHandler<OpenIddictServerEvents.ValidateTokenContext>
{
    public async ValueTask HandleAsync(OpenIddictServerEvents.ValidateTokenContext context)
    {
        if (string.IsNullOrEmpty(context.TokenId)) return;

        var token = await tokens.FindByIdAsync(context.TokenId);
        if (token is null
            || await tokens.GetTypeAsync(token) != TokenTypeIdentifiers.RefreshToken
            || !string.Equals(await tokens.GetStatusAsync(token), Statuses.Redeemed, StringComparison.Ordinal)) return;

        var authorizationId = await tokens.GetAuthorizationIdAsync(token);
        if (authorizationId is null) return;

        await tokens.RevokeByAuthorizationIdAsync(authorizationId);
        var authorization = await authorizations.FindByIdAsync(authorizationId);
        if (authorization is not null) await authorizations.TryRevokeAsync(authorization);

        _ = Guid.TryParse(await tokens.GetSubjectAsync(token), out var userId);
        await audit.RecordAsync(AuditEvents.RefreshReuseDetected, success: false, userId: userId == default ? null : userId,
            details: new { authorizationId, action = "authorization and all its tokens revoked" });
        log.LogWarning("Refresh token reuse detected; revoked authorization {AuthorizationId}", authorizationId);
    }
}
