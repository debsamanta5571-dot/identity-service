using Identity.Api.Data;
using Microsoft.AspNetCore.Authorization;
using OpenIddict.Abstractions;

namespace Identity.Api.Security;

/// <summary>One policy per scope: an endpoint declares the scope it needs and nothing else.</summary>
public static class ScopeAuthorization
{
    public static void AddScopePolicies(this AuthorizationOptions options)
    {
        foreach (var scope in SeedData.Scopes.Select(s => s.Name))
            options.AddPolicy("scope:" + scope, p => p.RequireAuthenticatedUser().RequireAssertion(c => c.User.HasScope(scope)));
    }

    public static TBuilder RequireScope<TBuilder>(this TBuilder builder, string scope) where TBuilder : IEndpointConventionBuilder =>
        builder.RequireAuthorization("scope:" + scope);
}
