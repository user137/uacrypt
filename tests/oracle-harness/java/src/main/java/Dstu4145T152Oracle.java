import java.math.BigInteger;

import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;

/** One-off oracle check for T-152 (docs/TASKS.md): does `curve163::scalar_multiply` in the Rust
 * code disagree with Bouncy Castle at/near the curve's own group order `n`? Computes
 * Q.multiply(n), Q.multiply(n-1), Q.multiply(n+1) for Q = 2G (order n, since n is odd for this
 * curve) via BC's own ECPoint arithmetic, independent of anything in the Rust implementation. */
public final class Dstu4145T152Oracle {
    public static void main(String[] args) {
        BigInteger ONE = BigInteger.ONE;
        BigInteger n = new BigInteger("400000000000000000002BEC12BE2262D39BCF14D", 16);
        ECCurve.F2m curve = new ECCurve.F2m(163, 3, 6, 7, ONE,
            new BigInteger("5FF6108462A2DC8210AB403925E638A19C1455D21", 16), n, null);
        ECPoint g = curve.createPoint(
            new BigInteger("72D867F93A93AC27DF9FF01AFFE74885C8C540420", 16),
            new BigInteger("0224A9C3947852B97C5599D5F4AB81122ADC3FD9B", 16));

        System.out.println("n            = " + n.toString(16).toUpperCase());
        System.out.println("g order check: g.multiply(n) = " + describe(g.multiply(n)));

        BigInteger TWO = BigInteger.valueOf(2);
        ECPoint q = g.multiply(TWO).normalize(); // Q = 2G, matches Rust's `G.double()`
        System.out.println();
        System.out.println("Q = 2G:");
        System.out.println("  Q.x           = " + q.getAffineXCoord().toBigInteger().toString(16).toUpperCase());
        System.out.println("  Q.y           = " + q.getAffineYCoord().toBigInteger().toString(16).toUpperCase());
        System.out.println("  Q.negate()    = " + describe(q.negate()));

        System.out.println();
        System.out.println("Q.multiply(n)   = " + describe(q.multiply(n)) + "   [expect: infinity]");
        System.out.println("Q.multiply(n-1) = " + describe(q.multiply(n.subtract(ONE))) + "   [expect: -Q, i.e. Q.negate()]");
        System.out.println("Q.multiply(n+1) = " + describe(q.multiply(n.add(ONE))) + "   [expect: Q itself]");
        System.out.println("Q.multiply(n-2) = " + describe(q.multiply(n.subtract(TWO))) + "   [expect: -2Q]");
        System.out.println("(-2Q) directly  = " + describe(q.multiply(TWO).negate()));

        boolean nMatches = q.multiply(n).normalize().isInfinity();
        boolean nMinus1Matches = q.multiply(n.subtract(ONE)).normalize().equals(q.negate().normalize());
        System.out.println();
        System.out.println("Q.multiply(n) is infinity?        " + nMatches);
        System.out.println("Q.multiply(n-1) equals -Q?         " + nMinus1Matches);
    }

    private static String describe(ECPoint p) {
        ECPoint n = p.normalize();
        if (n.isInfinity()) {
            return "INFINITY";
        }
        return "(" + n.getAffineXCoord().toBigInteger().toString(16).toUpperCase()
            + ", " + n.getAffineYCoord().toBigInteger().toString(16).toUpperCase() + ")";
    }
}
