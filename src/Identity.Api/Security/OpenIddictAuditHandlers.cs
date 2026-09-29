using Identity.Api.Security;
using OpenIddict.Abstractions;
using OpenIddict.Server;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace Identity.Api.Security;

/// <summary>Records every token issued by the token endpoint (code exchange and refresh).</summary>
public sealed class TokenIssuedAuditHandler(AuditService audit) : IOpenIddictServerHandler<OpenIddictServerEvents.ProcessSignInContext>
{
    public async ValueTask HandleAsync(OpenIddictServerEvents.ProcessSignInContext context)
    {
        if (context.EndpointType != OpenIddictServerEndpointType.Token || context.Principal is null) return;

        _ = Guid.TryParse(context.Principal.GetClaim(Claims.Subject), out var userId);
        await audit.RecordAsync(AuditEvents.TokenIssued, success: true, userId: userId == default ? null : userId,
            clientId: context.Request?.ClientId,
            details: new
            {
                grantType = context.Request?.GrantType,
                scopes = context.Principal.GetScopes(),
                authorizationId = context.Principal.GetAuthorizationId(),
            });
    }
}

/// <summary>Records revocation requests. The token's owner is not exposed at this point, so the client is recorded.</summary>
public sealed class RevocationAuditHandler(AuditService audit) : IOpenIddictServerHandler<OpenIddictServerEvents.ApplyRevocationResponseContext>
{
    public async ValueTask HandleAsync(OpenIddictServerEvents.ApplyRevocationResponseContext context) =>
        await audit.RecordAsync(AuditEvents.TokenRevoked, success: context.Error is null, clientId: context.Request?.ClientId,
            details: new { tokenTypeHint = context.Request?.TokenTypeHint, error = context.Error });
}
