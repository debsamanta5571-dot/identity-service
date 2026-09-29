using System.Net.Mail;

namespace Identity.Api.Security;

public static class Validation
{
    public const int MinPasswordLength = 12; // length over composition rules (NIST 800-63B)
    public const int MaxPasswordLength = 128; // bounds the Argon2 work an attacker can force

    public static string NormalizeEmail(string email) => email.Trim().ToLowerInvariant();

    public static bool IsValidEmail(string email) =>
        email.Length <= 254 && MailAddress.TryCreate(email, out var a) && a.Address == email && email.Contains('@');

    public static string? PasswordError(string password) => password.Length switch
    {
        < MinPasswordLength => $"Password must be at least {MinPasswordLength} characters.",
        > MaxPasswordLength => $"Password must be at most {MaxPasswordLength} characters.",
        _ => null,
    };
}
