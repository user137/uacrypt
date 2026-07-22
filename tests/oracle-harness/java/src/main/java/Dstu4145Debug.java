import java.math.BigInteger;

import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECFieldElement;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;

/** One-off: print DSTU4145Signer.verifySignature's intermediate values for the gf2m163.json
 * worked example, to localize a Rust implementation mismatch against the same computation. */
public final class Dstu4145Debug {
    private static final BigInteger ONE = BigInteger.ONE;

    public static void main(String[] args) {
        BigInteger n = new BigInteger("400000000000000000002BEC12BE2262D39BCF14D", 16);
        ECCurve.F2m curve = new ECCurve.F2m(163, 3, 6, 7, ONE,
            new BigInteger("5FF6108462A2DC8210AB403925E638A19C1455D21", 16), n, null);
        ECPoint g = curve.createPoint(
            new BigInteger("72D867F93A93AC27DF9FF01AFFE74885C8C540420", 16),
            new BigInteger("0224A9C3947852B97C5599D5F4AB81122ADC3FD9B", 16));
        ECPoint q = curve.createPoint(
            new BigInteger("057DE7FDE023FF929CB6AC785CE4B79CF64ABDC2DA", 16),
            new BigInteger("3E85444324BCF06AD85ABF6AD7B5F34770532B9AA", 16));
        byte[] hashJson = Hex.decode("09C9C44277910C9AAEE486883A2EB95B7180166DDF73532EEB76EDAEF52247FF");
        byte[] hash = Arrays.reverse(hashJson); // test163() pre-reverses before calling the signer
        BigInteger r = new BigInteger("274EA2C0CAA014A0D80A424F59ADE7A93068D08A7", 16);
        BigInteger s = new BigInteger("2100D86957331832B8E8C230F5BD6A332B3615ACA", 16);
        BigInteger d = new BigInteger("183F60FDF7951FF47D67193F8D073790C1C9B5A3E", 16);

        System.out.println("hash.length = " + hash.length);
        System.out.println("P.multiply(d) = " + g.multiply(d).normalize().getAffineXCoord().toBigInteger().toString(16).toUpperCase());
        System.out.println("P.multiply(d).negate() = " + g.multiply(d).negate().normalize().getAffineXCoord().toBigInteger().toString(16).toUpperCase());
        System.out.println("json public_key_q.x    = 057DE7FDE023FF929CB6AC785CE4B79CF64ABDC2DA");

        byte[] reversed = Arrays.reverse(hash);
        BigInteger dataInt = new BigInteger(1, reversed);
        System.out.println("reversed(hash) as BigInteger = " + dataInt.toString(16).toUpperCase());
        BigInteger truncated = dataInt.bitLength() > curve.getFieldSize()
            ? dataInt.mod(ONE.shiftLeft(curve.getFieldSize()))
            : dataInt;
        System.out.println("truncated to field size (" + curve.getFieldSize() + " bits) = "
            + truncated.toString(16).toUpperCase());

        ECFieldElement h = curve.fromBigInteger(truncated);
        if (h.isZero()) {
            h = curve.fromBigInteger(ONE);
        }
        System.out.println("h = " + h.toBigInteger().toString(16).toUpperCase());

        ECPoint sg = g.multiply(s);
        ECPoint rq = q.multiply(r);
        ECPoint bigR = sg.add(rq).normalize();
        System.out.println("R.x = " + bigR.getAffineXCoord().toBigInteger().toString(16).toUpperCase());
        System.out.println("R.y = " + bigR.getAffineYCoord().toBigInteger().toString(16).toUpperCase());

        ECFieldElement y = h.multiply(bigR.getAffineXCoord());
        System.out.println("y = h * R.x = " + y.toBigInteger().toString(16).toUpperCase());

        BigInteger rPrime = y.toBigInteger().bitLength() > (n.bitLength() - 1)
            ? y.toBigInteger().mod(ONE.shiftLeft(n.bitLength() - 1))
            : y.toBigInteger();
        System.out.println("r' = " + rPrime.toString(16).toUpperCase());
        System.out.println("expected r = " + r.toString(16).toUpperCase());
        System.out.println("match = " + rPrime.equals(r));
    }
}
