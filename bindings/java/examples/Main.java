// Run (from bindings/java, after `mvn compile`):
//   javac -cp target/classes -d target/examples-classes examples/*.java
//   java -cp "target/classes;target/examples-classes" Main <example>   (Windows)
//   java -cp "target/classes:target/examples-classes" Main <example>   (Linux/macOS)
// where <example> is one of: secretbox, box, secretstream-file, sign, password-hashing, misc

public final class Main {
    private Main() {
    }

    public static void main(String[] args) throws Exception {
        if (args.length != 1) {
            System.err.println("usage: java Main <secretbox|box|secretstream-file|sign|password-hashing|misc>");
            System.exit(1);
            return;
        }

        switch (args[0]) {
            case "secretbox":
                SecretBoxExample.run();
                break;
            case "box":
                BoxExample.run();
                break;
            case "secretstream-file":
                SecretStreamFileExample.run();
                break;
            case "sign":
                SignExample.run();
                break;
            case "password-hashing":
                PasswordHashingExample.run();
                break;
            case "misc":
                MiscExample.run();
                break;
            default:
                System.err.println("unknown example '" + args[0] + "'");
                System.exit(1);
        }
    }
}
