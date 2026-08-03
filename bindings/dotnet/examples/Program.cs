// Run: dotnet run -- <example>
// where <example> is one of: secretbox, secretstream-file, sign, password-hashing, misc

using DstuCore.Examples;

if (args.Length != 1)
{
    Console.Error.WriteLine("usage: dotnet run -- <secretbox|secretstream-file|sign|password-hashing|misc>");
    return 1;
}

switch (args[0])
{
    case "secretbox":
        SecretBoxExample.Run();
        break;
    case "secretstream-file":
        SecretStreamFileExample.Run();
        break;
    case "sign":
        SignExample.Run();
        break;
    case "password-hashing":
        PasswordHashingExample.Run();
        break;
    case "misc":
        MiscExample.Run();
        break;
    default:
        Console.Error.WriteLine($"unknown example '{args[0]}'");
        return 1;
}

return 0;
