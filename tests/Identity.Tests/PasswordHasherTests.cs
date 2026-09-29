using Identity.Api.Security;
using Microsoft.Extensions.Options;

namespace Identity.Tests;

public class PasswordHasherTests
{
    private static PasswordHasher Hasher(int memoryKiB = 1024) =>
        new(Options.Create(new Argon2Options { MemoryKiB = memoryKiB, Iterations = 2, Parallelism = 1 }));

    [Fact]
    public void Hash_uses_argon2id_phc_format_and_verifies()
    {
        var h = Hasher();
        var hash = h.Hash("correct-horse-battery");
        Assert.StartsWith("$argon2id$v=19$m=1024,t=2,p=1$", hash);
        Assert.True(h.Verify("correct-horse-battery", hash));
    }

    [Fact]
    public void Wrong_password_fails()
    {
        var h = Hasher();
        Assert.False(h.Verify("wrong-password-here", h.Hash("correct-horse-battery")));
    }

    [Fact]
    public void Same_password_gets_different_salt_each_time()
    {
        var h = Hasher();
        Assert.NotEqual(h.Hash("correct-horse-battery"), h.Hash("correct-horse-battery"));
    }

    [Fact]
    public void Hash_verifies_with_the_parameters_stored_in_it_even_if_config_changes()
    {
        var old = Hasher(memoryKiB: 1024).Hash("correct-horse-battery");
        Assert.True(Hasher(memoryKiB: 2048).Verify("correct-horse-battery", old));
    }

    [Theory]
    [InlineData("")]
    [InlineData("not-a-hash")]
    [InlineData("$argon2id$v=19$m=abc,t=2,p=1$c2FsdA$aGFzaA")]
    [InlineData("$bcrypt$v=19$m=1024,t=2,p=1$c2FsdA$aGFzaA")]
    [InlineData("$argon2id$v=19$m=1024,t=2$c2FsdA$aGFzaA")]
    public void Malformed_hash_returns_false_instead_of_throwing(string bad)
    {
        Assert.False(Hasher().Verify("anything", bad));
    }
}
