using System.Security.Cryptography;
using System.Text;
using Konscious.Security.Cryptography;
using Microsoft.Extensions.Options;

namespace Identity.Api.Security;

public sealed class Argon2Options
{
    // OWASP minimum for Argon2id: 19 MiB, 2 iterations, 1 lane.
    public int MemoryKiB { get; set; } = 19456;
    public int Iterations { get; set; } = 2;
    public int Parallelism { get; set; } = 1;
}

/// <summary>
/// Argon2id via Konscious (the KDF itself is not hand-rolled). This class only does salting, the
/// PHC string format and constant-time comparison. Parameters are stored in the hash, so raising
/// them later does not invalidate existing hashes.
/// </summary>
public sealed class PasswordHasher(IOptions<Argon2Options> options)
{
    private const int SaltBytes = 16;
    private const int HashBytes = 32;

    private readonly Lazy<string> _dummy = new(() => new PasswordHasher(options).Hash("dummy-password-for-timing"));

    /// <summary>Verified against when the user does not exist, so response time doesn't reveal which emails are registered.</summary>
    public string DummyHash => _dummy.Value;

    public string Hash(string password)
    {
        var o = options.Value;
        var salt = RandomNumberGenerator.GetBytes(SaltBytes);
        var hash = Compute(password, salt, o.MemoryKiB, o.Iterations, o.Parallelism, HashBytes);
        return $"$argon2id$v=19$m={o.MemoryKiB},t={o.Iterations},p={o.Parallelism}${B64(salt)}${B64(hash)}";
    }

    public bool Verify(string password, string phc)
    {
        try
        {
            var parts = phc.Split('$'); // "", argon2id, v=19, m=..,t=..,p=.., salt, hash
            if (parts.Length != 6 || parts[1] != "argon2id" || parts[2] != "v=19") return false;
            var kv = parts[3].Split(',').Select(x => x.Split('=')).ToDictionary(x => x[0], x => int.Parse(x[1]));
            var salt = FromB64(parts[4]);
            var expected = FromB64(parts[5]);
            var actual = Compute(password, salt, kv["m"], kv["t"], kv["p"], expected.Length);
            return CryptographicOperations.FixedTimeEquals(actual, expected);
        }
        catch (Exception e) when (e is FormatException or KeyNotFoundException or IndexOutOfRangeException or OverflowException)
        {
            return false;
        }
    }

    private static byte[] Compute(string password, byte[] salt, int memoryKiB, int iterations, int parallelism, int length)
    {
        using var argon = new Argon2id(Encoding.UTF8.GetBytes(password))
        {
            Salt = salt,
            MemorySize = memoryKiB,
            Iterations = iterations,
            DegreeOfParallelism = parallelism,
        };
        return argon.GetBytes(length);
    }

    private static string B64(byte[] b) => Convert.ToBase64String(b).TrimEnd('=');

    private static byte[] FromB64(string s) => Convert.FromBase64String(s.PadRight((s.Length + 3) / 4 * 4, '='));
}
