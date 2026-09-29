using System.Collections.Immutable;
using System.Security.Claims;
using Microsoft.IdentityModel.Tokens;
using OpenIddict.Abstractions;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace Identity.Api.Security;

/// <summary>
/// Builds the claims that end up in tokens. This is the policy layer: who gets which scopes is decided here,
/// from the user's roles, not by the OAuth library.
/// </summary>
public static class OAuthPrincipal
{
    public const string LedgerAudience = "ledger-api";
    public const string IdentityAudience = "identity-api";

    public static readonly string[] StandardScopes = [Scopes.OpenId, Scopes.Profile, Scopes.Email, Scopes.OfflineAccess];

    /// <summary>Scopes this user may hold: the union of their roles' scopes plus the standard OIDC ones.</summary>
    public static HashSet<string> Allowed(AuthenticatedUser user) => [.. StandardScopes, .. user.Scopes];

    public static ClaimsPrincipal Create(AuthenticatedUser user, string displayName, IEnumerable<string> requestedScopes)
    {
        var identity = new ClaimsIdentity(TokenValidationParameters.DefaultAuthenticationType, Claims.Name, Claims.Role);
        var principal = new ClaimsPrincipal(identity);
        identity.SetClaim(Claims.Subject, user.UserId.ToString());
        Apply(principal, displayName, user.Email, user.Roles, requestedScopes.Where(Allowed(user).Contains));
        principal.SetResources(LedgerAudience, IdentityAudience);
        return principal;
    }

    /// <summary>Re-derives roles and scopes from the database, so role changes take effect on the next refresh.</summary>
    public static void Refresh(ClaimsPrincipal principal, AuthenticatedUser user, string displayName)
    {
        var allowed = Allowed(user);
        Apply(principal, displayName, user.Email, user.Roles, principal.GetScopes().Where(allowed.Contains));
    }

    private static void Apply(ClaimsPrincipal principal, string name, string email, string[] roles, IEnumerable<string> scopes)
    {
        var identity = (ClaimsIdentity)principal.Identity!;
        identity.SetClaim(Claims.Name, name).SetClaim(Claims.Email, email).SetClaims(Claims.Role, roles.ToImmutableArray());
        var granted = scopes.Distinct().ToImmutableArray();
        principal.SetScopes(granted);
        var profile = granted.Contains(Scopes.Profile);
        principal.SetDestinations(claim => GetDestinations(claim, profile));
    }

    private static IEnumerable<string> GetDestinations(Claim claim, bool profileGranted) => claim.Type switch
    {
        // The display name also goes into the ACCESS token when the client asked for "profile", so an API (the ledger)
        // can label who did something in its audit trail. The email never does: APIs identify users by subject, and
        // personal contact data stays out of bearer tokens that are sent with every request.
        Claims.Name when profileGranted => [OpenIddictConstants.Destinations.AccessToken, OpenIddictConstants.Destinations.IdentityToken],
        Claims.Name or Claims.Email => [OpenIddictConstants.Destinations.IdentityToken],
        Claims.Subject => [OpenIddictConstants.Destinations.AccessToken, OpenIddictConstants.Destinations.IdentityToken],
        _ => [OpenIddictConstants.Destinations.AccessToken], // roles etc. go to the access token only
    };
}
