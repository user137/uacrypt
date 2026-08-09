import java.math.BigInteger;
import java.util.Random;

import org.bouncycastle.asn1.ua.DSTU4145PointEncoder;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECFieldElement;
import org.bouncycastle.math.ec.ECPoint;

/**
 * Generates unit-level GF(2^257) field-arithmetic and EC point-arithmetic test vectors for
 * DSTU 4145-2002's m=257 curve (T-199, docs/DECISIONS.md D-185/D-186).
 *
 * Curve/order/b parameters below are transcribed from two independently-issued real DSTU 4145
 * certificates (a czo.gov.ua test-CA cert and the project owner's own production Diia-issued
 * cert), byte-exact via dd-at-offset extraction, not hand-copied hex - see D-185/D-186 for the
 * full provenance. They independently match Bouncy Castle's own DSTU4145NamedCurves.java
 * curves[6] (m=257, k1=12, a=0, h=4) - so this file is a single-oracle (BC) generator exactly
 * like Dstu4145VectorGen.java is for m=163, not a from-scratch parameter re-derivation.
 *
 * IMPORTANT byte-order note (found running this generator, D-185 addendum): the certificate's own
 * signature-algorithm OID literally reads "DSTU 4145-2002 little endian" - its OCTET STRING-packed
 * field elements (b, the compressed base point) are byte-reversed relative to the canonical
 * big-endian hex BC/BigInteger expects, while the DER INTEGER order n is standard X.690 big-endian
 * and needed no reversal (confirmed: matches BC's n_s[6] verbatim). B and BP_COMPRESSED below are
 * therefore reversed from the certificate's raw bytes before use - exactly the "porting a
 * reference implementation means porting its calling convention too" failure mode CLAUDE.md's D-25
 * entry already documents for dstu4145's hash_to_field, now confirmed a second time here.
 *
 * The base point is stored DSTU4145-compressed in the certificates (DSTU4145PointEncoder, a
 * single field element plus a trace-parity bit packed into its low bit) - decompressed here via
 * BC's own DSTU4145PointEncoder.decodePoint rather than solving the curve equation by hand.
 *
 * Build/run (from this directory):
 *   javac -cp lib/bcprov-jdk18on-1.85.jar -d out src/main/java/Dstu4145VectorGen257.java
 *   java -cp "out;lib/bcprov-jdk18on-1.85.jar" Dstu4145VectorGen257 > \
 *       ../../../crates/dstu-core/tests/vectors/dstu4145/gf2m257_arith.json
 */
public final class Dstu4145VectorGen257 {

    private static final BigInteger ZERO = BigInteger.ZERO;
    private static final BigInteger ONE = BigInteger.ONE;
    // Reversed from the certificate's raw little-endian OCTET STRING bytes (see class doc) -
    // confirmed numerically equal to BC's own DSTU4145NamedCurves.java curves[6] b constant.
    private static final BigInteger B =
        new BigInteger("1CEF494720115657E18F938D7A7942394FF9425C1458C57861F9EEA6ADBE3BE10", 16);
    private static final BigInteger N =
        new BigInteger("800000000000000000000000000000006759213AF182E987D3E17714907D470D", 16);
    // Reversed from the certificate's raw little-endian compressed base-point bytes (see class doc).
    private static final byte[] BP_COMPRESSED = hexBytes(
        "002A29EF207D0E9B6C55CD260B306C7E007AC491CA1B10C62334A9E8DCD8D20FB6");

    private static final int FIELD_CASE_COUNT = 20;
    private static final int POINT_CASE_COUNT = 20;
    private static final int SIGNATURE_CASE_COUNT = 20;

    public static void main(String[] args) {
        ECCurve.F2m curve = new ECCurve.F2m(257, 12, ZERO, B, N, null);
        ECPoint g = DSTU4145PointEncoder.decodePoint(curve, BP_COMPRESSED).normalize();
        if (!g.isValid()) {
            throw new IllegalStateException("decompressed base point fails BC's own curve-equation check");
        }

        Random rnd = new Random(0x44535455_34313435L /* "DSTU4145" folded into a long, same seed convention as the m=163 generator */);

        StringBuilder out = new StringBuilder();
        out.append("{\n");
        out.append("  \"algorithm\": \"DSTU 4145-2002 GF(2^257) field + EC point arithmetic ")
            .append("(unit-level, generated)\",\n");
        out.append("  \"field_bits\": 257,\n");
        out.append("  \"reduction_polynomial\": \"x^257 + x^12 + 1\",\n");
        out.append("  \"source\": \"Generated via Bouncy Castle's ECFieldElement.F2m/ECPoint.F2m ")
            .append("(published bcprov-jdk18on 1.85, see docs/ORACLES.md) against curve/order/b ")
            .append("parameters extracted from two independent real DSTU 4145 certificates (czo.gov.ua ")
            .append("test CA + a real Diia-issued production certificate), byte-verified against ")
            .append("Bouncy Castle's own DSTU4145NamedCurves.java curves[6] - see docs/DECISIONS.md ")
            .append("D-185/D-186. Base point decompressed via BC's own DSTU4145PointEncoder.decodePoint. ")
            .append("Single-oracle at the unit level (BC only) - docs/DECISIONS.md D-185 flags this as ")
            .append("still provisional pending direct cross-check against the DSTU 4145-2002 Annex Г ")
            .append("text itself, same posture as gf2m163_arith.json's own single-oracle caveat.\",\n");
        out.append("  \"curve\": { \"a\": \"0\", \"b\": \"").append(hex(B)).append("\" },\n");
        out.append("  \"order_n\": \"").append(hex(N)).append("\",\n");
        out.append("  \"base_point\": { \"x\": \"")
            .append(hex(g.getAffineXCoord().toBigInteger())).append("\", \"y\": \"")
            .append(hex(g.getAffineYCoord().toBigInteger())).append("\" },\n");

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
        out.append("\n  ],\n");

        // "signature_cases": tests dstu_core::hazmat::dstu4145::signature257's post-hash logic
        // (curve/scalar composition) directly against BC's own field/point arithmetic, bypassing
        // BC's own hash2FieldElement (whose pre-reversed-input convention is a known, separately
        // handled quirk for m=163, docs/pseudocode/dstu4145.md - not touched here). `h` is chosen
        // as a random field element directly rather than derived from a "message" - since
        // signature257::hash_to_field(h.to_be_bytes()) == h exactly for any already-valid field
        // element (no reversal, no truncation needed when the input is already a full 33-byte
        // field-element encoding), this exercises the same code path a real hash digest would,
        // without needing BC's hash2FieldElement at all.
        BigInteger n = N;
        out.append("  \"signature_cases\": [\n");
        for (int i = 0; i < SIGNATURE_CASE_COUNT; i++) {
            BigInteger d = randomScalar(rnd);
            BigInteger e = randomScalar(rnd);
            BigInteger hInt = randomFieldElement(rnd, curve);
            ECFieldElement h = curve.fromBigInteger(hInt);

            ECPoint q = g.multiply(d).normalize();
            ECFieldElement qxNeg = q.getAffineXCoord();
            ECFieldElement qyNeg = qxNeg.add(q.getAffineYCoord()); // negate: (x, x+y)

            ECPoint fePoint = g.multiply(e).normalize();
            ECFieldElement fe = fePoint.getAffineXCoord();
            ECFieldElement y = h.multiply(fe);
            // truncate(y, n.bit_length() - 1) = truncate(y, 255) - N's bit-length is 256, not 257
            // (its top byte 0x80 has no leading-zero slack), found the hard way when this mask was
            // originally 256 (docs/DECISIONS.md D-185/D-186 addendum, docs/TASKS.md T-199).
            BigInteger r = y.toBigInteger().and(BigInteger.ONE.shiftLeft(255).subtract(ONE));
            BigInteger s = r.multiply(d).add(e).mod(n);

            out.append("    { \"d\": \"").append(hex(d))
                .append("\", \"e\": \"").append(hex(e))
                .append("\", \"h\": \"").append(hex(hInt))
                .append("\", \"qx\": \"").append(hex(qxNeg.toBigInteger()))
                .append("\", \"qy\": \"").append(hex(qyNeg.toBigInteger()))
                .append("\", \"r\": \"").append(hex(r))
                .append("\", \"s\": \"").append(hex(s))
                .append("\" },\n");
        }
        out.setLength(out.length() - 2);
        out.append("\n  ]\n");
        out.append("}\n");

        System.out.print(out);
    }

    /** Uniform in [1, 2^257 - 1], i.e. nonzero and within the field's representable range. */
    private static BigInteger randomFieldElement(Random rnd, ECCurve curve) {
        BigInteger v;
        do {
            byte[] bytes = new byte[33]; // 264 bits, masked down to 257
            rnd.nextBytes(bytes);
            bytes[0] &= 0x01; // keep only the low bit of the top byte -> <= 257 bits total
            v = new BigInteger(1, bytes);
        } while (v.signum() == 0);
        return v;
    }

    private static BigInteger randomScalar(Random rnd) {
        BigInteger v;
        do {
            byte[] bytes = new byte[34];
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

    private static byte[] hexBytes(String s) {
        byte[] b = new byte[s.length() / 2];
        for (int i = 0; i < b.length; i++) {
            b[i] = (byte) Integer.parseInt(s.substring(i * 2, i * 2 + 2), 16);
        }
        return b;
    }
}
