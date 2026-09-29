namespace Identity.Api.Endpoints;

public sealed record CreateUserRequest(string? Email, string? Password, string? DisplayName, string[]? Roles);
public sealed record SetRolesRequest(string[]? Roles);
public sealed record CreateRoleRequest(string? Name, string? Description, string[]? Scopes);

public sealed record SetStatusRequest(bool? IsActive);
public sealed record UserDto(Guid Id, string Email, string DisplayName, bool IsActive, string[] Roles, DateTimeOffset CreatedAt, bool MfaEnabled, DateTimeOffset? LockedUntil);
public sealed record RoleDto(Guid Id, string Name, string Description, string[] Scopes);
public sealed record ScopeDto(string Name, string Description);
