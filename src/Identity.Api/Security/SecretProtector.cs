using System.Security.Cryptography;

namespace Identity.Api.Security;

/// <summary>
/// Encrypts TOTP secrets at rest with AES-256-GCM (platform crypto). A database leak alone does not reveal
/// them; the key lives in configuration/secret store (Mfa:EncryptionKey, 32 bytes base64), not in the database.
/// Layout: nonce(12) | tag(16) | ciphertext.
/// </summary>
public sealed class SecretProtector(IConfiguration config)
{
    private const int NonceSize = 12, TagSize = 16;

    private byte[] Key()
    {
        var b64 = config["Mfa:EncryptionKey"] ?? throw new InvalidOperationException("Mfa:EncryptionKey is not configured.");
        var key = Convert.FromBase64String(b64);
        return key.Length == 32 ? key : throw new InvalidOperationException("Mfa:EncryptionKey must be 32 bytes (base64).");
    }

    public byte[] Protect(byte[] plaintext)
    {
        var nonce = RandomNumberGenerator.GetBytes(NonceSize);
        var cipher = new byte[plaintext.Length];
        var tag = new byte[TagSize];
        using var aes = new AesGcm(Key(), TagSize);
        aes.Encrypt(nonce, plaintext, cipher, tag);
        return [.. nonce, .. tag, .. cipher];
    }

    public byte[] Unprotect(byte[] blob)
    {
        var nonce = blob.AsSpan(0, NonceSize);
        var tag = blob.AsSpan(NonceSize, TagSize);
        var cipher = blob.AsSpan(NonceSize + TagSize);
        var plain = new byte[cipher.Length];
        using var aes = new AesGcm(Key(), TagSize);
        aes.Decrypt(nonce, cipher, tag, plain); // throws if the blob was tampered with
        return plain;
    }
}
