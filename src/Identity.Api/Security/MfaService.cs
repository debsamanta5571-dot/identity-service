using System.Security.Cryptography;
using System.Text;
using Identity.Api.Data;
using Identity.Api.Domain;
using Microsoft.EntityFrameworkCore;
using QRCoder;

namespace Identity.Api.Security;

public enum MfaMethod { Totp, Recovery }

public sealed record MfaEnrollment(string Secret, string OtpauthUri, string QrCodePng);

public sealed class MfaService(IdentityDbContext db, SecretProtector protector, TimeProvider clock, IConfiguration config)
{
    private const int RecoveryCodeCount = 10;

    /// <summary>Starts enrollment: a fresh secret is stored (encrypted) but MFA stays off until a code is confirmed.</summary>
    public async Task<MfaEnrollment?> EnrollAsync(Guid userId, CancellationToken ct)
    {
        var user = await db.Users.SingleOrDefaultAsync(u => u.Id == userId, ct);
        if (user is null || user.MfaEnabled) return null;

        var secret = RandomNumberGenerator.GetBytes(20); // 160 bits, the RFC 4226 recommendation
        user.MfaSecret = protector.Protect(secret);
        user.MfaLastStep = null;
        user.UpdatedAt = clock.GetUtcNow();
        await db.SaveChangesAsync(ct);

        var base32 = Totp.Base32Encode(secret);
        var uri = Totp.ProvisioningUri(config["Mfa:Issuer"] ?? "Identity Service", user.Email, base32);
        using var generator = new QRCodeGenerator();
        using var data = generator.CreateQrCode(uri, QRCodeGenerator.ECCLevel.M);
        var png = new PngByteQRCode(data).GetGraphic(8);
        return new MfaEnrollment(base32, uri, "data:image/png;base64," + Convert.ToBase64String(png));
    }

    /// <summary>Proves the user's app works: a valid code switches MFA on and returns recovery codes (shown once).</summary>
    public async Task<string[]?> ConfirmEnrollmentAsync(Guid userId, string code, CancellationToken ct)
    {
        var user = await db.Users.SingleOrDefaultAsync(u => u.Id == userId, ct);
        if (user is null || user.MfaEnabled || user.MfaSecret is null) return null;

        var step = Totp.Match(protector.Unprotect(user.MfaSecret), Normalize(code), clock.GetUtcNow(), user.MfaLastStep);
        if (step is null) return null;

        var codes = Enumerable.Range(0, RecoveryCodeCount).Select(_ => NewRecoveryCode()).ToArray();
        await using var tx = await db.Database.BeginTransactionAsync(ct);
        await db.RecoveryCodes.Where(r => r.UserId == userId).ExecuteDeleteAsync(ct);
        foreach (var c in codes) db.RecoveryCodes.Add(new RecoveryCode { UserId = userId, CodeHash = Hash(Normalize(c)) });
        user.MfaEnabled = true;
        user.MfaLastStep = step;
        user.UpdatedAt = clock.GetUtcNow();
        await db.SaveChangesAsync(ct);
        await tx.CommitAsync(ct);
        return codes;
    }

    /// <summary>Turning MFA off needs a current code, so a stolen session alone can't remove the second factor.</summary>
    public async Task<bool> DisableAsync(Guid userId, string code, CancellationToken ct)
    {
        var user = await db.Users.AsNoTracking().SingleOrDefaultAsync(u => u.Id == userId, ct);
        if (user is null || !user.MfaEnabled || await VerifyLoginCodeAsync(user, code, ct) is null) return false;

        await db.RecoveryCodes.Where(r => r.UserId == userId).ExecuteDeleteAsync(ct);
        await db.Users.Where(u => u.Id == userId).ExecuteUpdateAsync(s => s
            .SetProperty(u => u.MfaEnabled, false)
            .SetProperty(u => u.MfaSecret, (byte[]?)null)
            .SetProperty(u => u.MfaLastStep, (long?)null)
            .SetProperty(u => u.UpdatedAt, clock.GetUtcNow()), ct);
        return true;
    }

    /// <summary>
    /// A 6-digit TOTP code or a recovery code. Both are consumed atomically in the database
    /// (UPDATE ... WHERE not-yet-used), so two concurrent requests with the same code cannot both succeed.
    /// </summary>
    public async Task<MfaMethod?> VerifyLoginCodeAsync(User user, string code, CancellationToken ct)
    {
        var normalized = Normalize(code);
        if (user.MfaSecret is null || normalized.Length == 0) return null;

        if (normalized.Length == Totp.Digits)
        {
            var step = Totp.Match(protector.Unprotect(user.MfaSecret), normalized, clock.GetUtcNow(), user.MfaLastStep);
            if (step is null) return null;
            var rows = await db.Users
                .Where(u => u.Id == user.Id && (u.MfaLastStep == null || u.MfaLastStep < step))
                .ExecuteUpdateAsync(s => s.SetProperty(u => u.MfaLastStep, step), ct);
            return rows == 1 ? MfaMethod.Totp : null;
        }

        var hash = Hash(normalized);
        var used = await db.RecoveryCodes
            .Where(r => r.UserId == user.Id && r.CodeHash == hash && r.UsedAt == null)
            .ExecuteUpdateAsync(s => s.SetProperty(r => r.UsedAt, clock.GetUtcNow()), ct);
        return used == 1 ? MfaMethod.Recovery : null;
    }

    private static string Normalize(string code) => new(code.Where(char.IsLetterOrDigit).Select(char.ToUpperInvariant).ToArray());

    // Recovery codes carry 80 random bits, so a fast unsalted hash is safe here (nothing to brute-force);
    // passwords need Argon2 because they are low-entropy.
    private static string Hash(string normalized) => Convert.ToHexString(SHA256.HashData(Encoding.ASCII.GetBytes(normalized)));

    private static string NewRecoveryCode()
    {
        var b32 = Totp.Base32Encode(RandomNumberGenerator.GetBytes(10)); // 16 chars
        return $"{b32[..4]}-{b32[4..8]}-{b32[8..12]}-{b32[12..]}";
    }
}
