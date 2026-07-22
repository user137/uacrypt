import java.math.BigInteger;
import java.util.Random;

import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECFieldElement;
import org.bouncycastle.math.ec.ECPoint;

/**
 * Generates unit-level GF(2^163) field-arithmetic and EC point-arithmetic test vectors for the
 * DSTU 4145-2002 curve used in crates/dstu-core/tests/vectors/dstu4145/gf2m163.json (curve
 * params, base point, and order n copied verbatim from that file / DSTU4145Test.java test163(),
 * both already dual-sourced - see DECISIONS.md D-14).
 *
 * Unlike gf2m163.json (spec Annex B worked example, cross-checked against BC), this generator
 * makes Bouncy Castle the sole source of truth: it exercises BC's own
 * org.bouncycastle.math.ec.ECFieldElement.F2m / ECPoint.F2m implementation directly and freezes
 * the output. Single-oracle, not dual-sourced at the unit level - documented as such in
 * DECISIONS.md (see the entry citing this file) rather than overclaimed. The reason this exists at
 * all: gf2m163.json only has signature-level values (final r, s), nothing at the level of a single
 * field multiplication/inversion or a single point doubling/addition, so it can't test-first the
 * arithmetic layer on its own - see TASKS.md Phase 2 / DSTU 4145.
 *
 * Deterministic (fixed java.util.Random seed - reproducible per the Java Language Spec's own
 * linear-congruential definition, same reasoning as this project's splitmix64 generators
 * elsewhere, just not the same algorithm since nothing here needs to match them byte-for-byte).
 *
 * Build/run (from this directory, reuses the same bcprov-jdk18on-1.85.jar already vendored for
 * OracleHarness.java):
 *   javac -cp lib/bcprov-jdk18on-1.85.jar -d out src/main/java/Dstu4145VectorGen.java
 *   java -cp "out;lib/bcprov-jdk18on-1.85.jar" Dstu4145VectorGen > \
 *       ../../../crates/dstu-core/tests/vectors/dstu4145/gf2m163_arith.json
 */
public final class Dstu4145VectorGen {

    private static final BigInteger ONE = BigInteger.ONE;
    private static final BigInteger B =
        new BigInteger("5FF6108462A2DC8210AB403925E638A19C1455D21", 16);
    private static final BigInteger N =
        new BigInteger("400000000000000000002BEC12BE2262D39BCF14D", 16);
    private static final BigInteger GX =
        new BigInteger("72D867F93A93AC27DF9FF01AFFE74885C8C540420", 16);
    private static final BigInteger GY =
        new BigInteger("0224A9C3947852B97C5599D5F4AB81122ADC3FD9B", 16);

    private static final int FIELD_CASE_COUNT = 20;
    private static final int POINT_CASE_COUNT = 20;

    public static void main(String[] args) {
        ECCurve.F2m curve = new ECCurve.F2m(163, 3, 6, 7, ONE, B, N, null);
        ECPoint g = curve.createPoint(GX, GY).normalize();
        if (!g.isValid()) {
            throw new IllegalStateException("base point fails BC's own curve-equation check");
        }

        Random rnd = new Random(0x44535455_34313435L /* "DSTU4145" folded into a long, arbitrary */);

        StringBuilder out = new StringBuilder();
        out.append("{\n");
        out.append("  \"algorithm\": \"DSTU 4145-2002 GF(2^163) field + EC point arithmetic ")
            .append("(unit-level, generated)\",\n");
        out.append("  \"field_bits\": 163,\n");
        out.append("  \"reduction_polynomial\": \"x^163 + x^7 + x^6 + x^3 + 1\",\n");
        out.append("  \"source\": \"Generated via Bouncy Castle's ECFieldElement.F2m/ECPoint.F2m ")
            .append("(published bcprov-jdk18on 1.85, see ORACLES.md) against the curve/base-point/")
            .append("order already dual-sourced in gf2m163.json - tests/oracle-harness/java/src/main")
            .append("/java/Dstu4145VectorGen.java. Single-oracle at the unit level (BC only), not ")
            .append("dual-sourced the way gf2m163.json is - see DECISIONS.md.\",\n");
        out.append("  \"curve\": { \"a\": \"1\", \"b\": \"").append(hex(B)).append("\" },\n");
        out.append("  \"order_n\": \"").append(hex(N)).append("\",\n");
        out.append("  \"base_point\": { \"x\": \"").append(hex(GX)).append("\", \"y\": \"")
            .append(hex(GY)).append("\" },\n");

        out.append("  \"field_cases\": [\n");
        for (int i = 0; i < FIELD_CASE_COUNT; i++) {
            BigInteger a = randomFieldElement(rnd, curve);
            BigInteger b = randomFieldElement(rnd, curve);
            ECFieldElement fa = curve.fromBigInteger(a);
            ECFieldElement fb = curve.fromBigInteger(b);

            appendFieldCase(out, "add", a, b, fa.add(fb).toBigInteger());
            appendFieldCase(out, "multiply", a, b, fa.multiply(fb).toBigInteger());
            appendFieldCase(out, "square", a, null, fa.square().toBigInteger());
            appendFieldCase(out, "invert", a, null, fa.invert().toBigInteger());
        }
        out.setLength(out.length() - 2); // drop trailing ",\n"
        out.append("\n  ],\n");

        out.append("  \"point_cases\": [\n");
        for (int i = 0; i < POINT_CASE_COUNT; i++) {
            BigInteger k1 = randomScalar(rnd);
            BigInteger k2 = randomScalar(rnd);
            ECPoint p = g.multiply(k1).normalize();
            ECPoint q = g.multiply(k2).normalize();

            appendPointDoubleCase(out, p);
            appendPointAddCase(out, p, q);
            appendScalarMultiplyCase(out, k1, p);
        }
        out.setLength(out.length() - 2);
        out.append("\n  ]\n");
        out.append("}\n");

        System.out.print(out);
    }

    /** Uniform in [1, 2^163 - 1], i.e. nonzero and within the field's representable range. */
    private static BigInteger randomFieldElement(Random rnd, ECCurve curve) {
        BigInteger v;
        do {
            byte[] bytes = new byte[21]; // 168 bits, masked down to 163
            rnd.nextBytes(bytes);
            bytes[0] &= 0x07; // keep only the low 3 bits of the top byte -> <= 163 bits total
            v = new BigInteger(1, bytes);
        } while (v.signum() == 0);
        return v;
    }

    private static BigInteger randomScalar(Random rnd) {
        BigInteger v;
        do {
            byte[] bytes = new byte[22];
            rnd.nextBytes(bytes);
            v = new BigInteger(1, bytes).mod(N);
        } while (v.signum() == 0);
        return v;
    }

    private static void appendFieldCase(StringBuilder out, String op, BigInteger a, BigInteger b,
                                         BigInteger result) {
        out.append("    { \"op\": \"").append(op).append("\", \"a\": \"").append(hex(a))
            .append("\"");
        if (b != null) {
            out.append(", \"b\": \"").append(hex(b)).append("\"");
        }
        out.append(", \"result\": \"").append(hex(result)).append("\" },\n");
    }

    private static void appendPointDoubleCase(StringBuilder out, ECPoint p) {
        ECPoint r = p.twice().normalize();
        out.append("    { \"op\": \"double\", \"px\": \"")
            .append(hex(p.getAffineXCoord().toBigInteger())).append("\", \"py\": \"")
            .append(hex(p.getAffineYCoord().toBigInteger())).append("\", \"rx\": \"")
            .append(hex(r.getAffineXCoord().toBigInteger())).append("\", \"ry\": \"")
            .append(hex(r.getAffineYCoord().toBigInteger())).append("\" },\n");
    }

    private static void appendPointAddCase(StringBuilder out, ECPoint p, ECPoint q) {
        ECPoint r = p.add(q).normalize();
        out.append("    { \"op\": \"add\", \"px\": \"")
            .append(hex(p.getAffineXCoord().toBigInteger())).append("\", \"py\": \"")
            .append(hex(p.getAffineYCoord().toBigInteger())).append("\", \"qx\": \"")
            .append(hex(q.getAffineXCoord().toBigInteger())).append("\", \"qy\": \"")
            .append(hex(q.getAffineYCoord().toBigInteger())).append("\", \"rx\": \"")
            .append(hex(r.getAffineXCoord().toBigInteger())).append("\", \"ry\": \"")
            .append(hex(r.getAffineYCoord().toBigInteger())).append("\" },\n");
    }

    private static void appendScalarMultiplyCase(StringBuilder out, BigInteger k, ECPoint p) {
        out.append("    { \"op\": \"scalar_multiply\", \"k\": \"").append(hex(k))
            .append("\", \"rx\": \"").append(hex(p.getAffineXCoord().toBigInteger()))
            .append("\", \"ry\": \"").append(hex(p.getAffineYCoord().toBigInteger()))
            .append("\" },\n");
    }

    private static String hex(BigInteger v) {
        String h = v.toString(16).toUpperCase();
        return h.length() % 2 == 0 ? h : "0" + h;
    }
}
