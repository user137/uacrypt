using System.Text;
using DstuCore;

namespace DstuCore.Examples;

/// <summary><c>crypto_pwhash</c> (Argon2id): hash and verify a password.
///
/// <see cref="PwhashStrength.Interactive"/> is used here so the example runs fast -
/// <see cref="PwhashStrength.Moderate"/> (the strength most applications should use) and
/// <see cref="PwhashStrength.Sensitive"/> both take real seconds by design.</summary>
internal static class PasswordHashingExample
{
    public static void Run()
    {
        var password = Encoding.ASCII.GetBytes("correct horse battery staple");
        var stored = Pwhash.HashPassword(password, PwhashStrength.Interactive);
        Console.WriteLine($"stored hash: {stored}");

        if (!Pwhash.VerifyPassword(password, stored))
        {
            throw new InvalidOperationException("correct password was rejected");
        }

        Console.WriteLine("correct password accepted");

        if (!Pwhash.VerifyPassword(Encoding.ASCII.GetBytes("wrong guess"), stored))
        {
            Console.WriteLine("wrong password correctly rejected");
        }
    }
}
