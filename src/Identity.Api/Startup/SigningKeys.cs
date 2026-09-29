using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.IdentityModel.Tokens;
using OpenIddict.Server;

namespace Identity.Api.Startup;

/// <summary>
/// Loads token signing/encryption material from configuration (env vars / secret store), never from source.
///
/// Rotation: register several certificates. OpenIddict signs with the certificate that expires last and
/// publishes every registered key in the JWKS, so adding a new, later-expiring certificate rotates signing
/// while tokens signed by the old key still verify until you remove it.
///
/// Only Development may fall back to ephemeral keys (tokens then die on restart).
/// </summary>
public static class SigningKeys
{
    public static void Apply(OpenIddictServerOptions o, IConfiguration cfg, IHostEnvironment env)
    {
        var certs = cfg.GetSection("Signing:Certificates").GetChildren().ToList();
        foreach (var c in certs)
        {
            var pfx = c["Pfx"] ?? throw new InvalidOperationException("Signing:Certificates:*:Pfx is missing.");
            var cert = new X509Certificate2(Convert.FromBase64String(pfx), c["Password"], X509KeyStorageFlags.EphemeralKeySet);
            if (!cert.HasPrivateKey) throw new InvalidOperationException($"Certificate {cert.Thumbprint} has no private key.");
            o.SigningCredentials.Add(new SigningCredentials(new X509SecurityKey(cert), SecurityAlgorithms.RsaSha256)); // RS256
        }
        if (certs.Count == 0)
        {
            if (!env.IsDevelopment()) throw new InvalidOperationException("Signing:Certificates is not configured.");
            var key = new RsaSecurityKey(RSA.Create(2048)) { KeyId = Guid.NewGuid().ToString("N") };
            o.SigningCredentials.Add(new SigningCredentials(key, SecurityAlgorithms.RsaSha256));
        }

        // Refresh tokens and authorization codes are encrypted JWTs; this symmetric key protects them.
        var enc = cfg["Signing:EncryptionKey"];
        byte[] bytes;
        if (enc is not null) bytes = Convert.FromBase64String(enc);
        else if (env.IsDevelopment()) bytes = RandomNumberGenerator.GetBytes(32);
        else throw new InvalidOperationException("Signing:EncryptionKey is not configured.");
        if (bytes.Length != 32) throw new InvalidOperationException("Signing:EncryptionKey must be 32 bytes (base64).");
        o.EncryptionCredentials.Add(new EncryptingCredentials(new SymmetricSecurityKey(bytes),
            SecurityAlgorithms.Aes256KW, SecurityAlgorithms.Aes256CbcHmacSha512));
    }
}
