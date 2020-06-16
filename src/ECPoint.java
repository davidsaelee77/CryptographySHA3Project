import java.math.BigDecimal;
import java.math.BigInteger;

public class ECPoint {
    /**
     * Variable to store point X (Defaulted to 4).
     */
    private final BigInteger x;
    /**
     * Variable to store point Y (An even number).
     */
    private final BigInteger y;
    /**
     * Mersenne Prime number.
     */
    public final BigInteger pBI;
    /**
     * Edwards curve 4r (the number or points on a curve).
     */
    public final BigInteger rBI;
    /**
     * A square in K.  K is a field that does not have a characteristic 2.
     */
    public final int d = -376014;
    /**
     * The neutral element of addition (defaulted to (0,1)).
     */
    public static ECPoint Point0 = new ECPoint(BigInteger.ZERO, BigInteger.ONE);

    /**
     * Elliptic curve point constructor that takes two big integer arguments.
     *
     * @param x coordinate on the curve.
     * @param y coordinate on the curve.
     */
    public ECPoint(BigInteger x, BigInteger y) {
        this.x = x;
        this.y = y;
        //Converts Mersenne prime into a BigInteger.
        double p = Math.pow(2, 521) - 1;
        BigDecimal decimalP = new BigDecimal(p);
        pBI = decimalP.toBigInteger();

        //Converts R into a BigInteger.
        BigInteger largeNumber = new BigInteger("337554763258501705789107630418782636071904961214051226618635150085779108655765");
        double r = Math.pow(2, 519);
        BigDecimal decimalR = new BigDecimal(r);
        rBI = decimalR.toBigInteger().subtract(largeNumber);

    }

    /**
     * Returns X coordinate.
     *
     * @return X coordinate.
     */
    public BigInteger getX() {
        return x;
    }

    /**
     * Returns Y coordinate.
     *
     * @return Y coordinate.
     */
    public BigInteger getY() {
        return y;
    }

    /**
     * Implements Edward's curve elliptic curve arithmetic.
     *
     * @param otherPoint point used for arithmetic computation.
     * @return a newly computed X and Y coordinate.
     */
    public static ECPoint pointSum(ECPoint thisPoint, ECPoint otherPoint) {

        int d = -376014;
        double p = Math.pow(2, 521) - 1;
        BigDecimal decimalP = new BigDecimal(p);
        BigInteger pBI = decimalP.toBigInteger();

        BigInteger dBI = BigInteger.valueOf(d);

        BigInteger x1y2 = thisPoint.getX().multiply(otherPoint.getY()).mod(pBI);
        BigInteger y1x2 = thisPoint.getY().multiply(otherPoint.getX()).mod(pBI);
        BigInteger xNumerator = x1y2.add(y1x2).mod(pBI);
        BigInteger xDenominator = BigInteger.ONE.add(dBI.multiply(x1y2).multiply(y1x2));
        BigInteger newX = xNumerator.multiply(xDenominator.modInverse(pBI)).mod(pBI);

        BigInteger y1y2 = thisPoint.getY().multiply(otherPoint.getY()).mod(pBI);
        BigInteger x1x2 = thisPoint.getX().multiply(otherPoint.getX()).mod(pBI);
        BigInteger yNumerator = y1y2.subtract(x1x2).mod(pBI);
        BigInteger yDenominator = BigInteger.ONE.subtract(dBI.multiply(y1y2).multiply(x1x2));
        BigInteger newY = yNumerator.multiply(yDenominator.modInverse(pBI)).mod(pBI);

        return new ECPoint(newX, newY);
    }

    /**
     * Compares two points for equality.
     *
     * @param object another point used for comparison.
     * @return true if points are the same or false if not the same.
     */
    public boolean pointEquals(Object object) {

        ECPoint point = (ECPoint) object;
        boolean flag = false;
        if (this.y.equals(point.getY())) {
            flag = true;
        } else if (this.x.equals(point.getX())) {

            flag = true;
        }
        return flag;

    }

    /**
     * Determines if the point is the inverse/opposite.
     * The opposite of (X, Y) == (-X, Y).
     *
     * @param object another point uses for comparison.
     * @return a opposite X coordinate (negated).
     */
    public ECPoint Opposite(Object object) {

        ECPoint point = (ECPoint) object;

        BigInteger newX;

        if (this.x.equals(point.getX())) {

            newX = this.x.negate();

        } else {

            newX = this.x;
        }

        return new ECPoint(newX, this.y);
    }

    /**
     * Checks the Y coordinate to determine if coordinate is even.
     *
     * @param P another point for comparison.
     * @return a new point with the least significant bit.
     */
    public ECPoint LSBOFY(ECPoint P) {

        int d = 376014;
        BigInteger dBI = BigInteger.valueOf(d);
        BigInteger xSqr = P.getX().pow(2);
        BigInteger numerator = BigInteger.ONE.subtract(xSqr);
        BigInteger dXsqr = dBI.multiply(xSqr);
        BigInteger demoninator = BigInteger.ONE.add(dXsqr);

        BigInteger lsbY = sqrt(numerator.divide(demoninator), pBI, true);

        return new ECPoint(P.x, lsbY);
    }

    /**
     * Compute a square root of v mod p with a specified
     * least significant bit, if such a root exists.
     *
     * @param v   the radicand.
     * @param p   the modulus (must satisfy p mod 4 = 3).
     * @param lsb desired least significant bit (true: 1, false: 0).
     * @return a square root r of v mod p with r mod 2 = 1 iff lsb = true
     * if such a root exists, otherwise null.
     */
    public static BigInteger sqrt(BigInteger v, BigInteger p, boolean lsb) {
        assert (p.testBit(0) && p.testBit(1)); // p = 3 (mod 4)
        if (v.signum() == 0) {
            return BigInteger.ZERO;
        }
        BigInteger r = v.modPow(p.shiftRight(2).add(BigInteger.ONE), p);
        if (r.testBit(0) != lsb) {
            r = p.subtract(r); // correct the lsb
        }
        return (r.multiply(r).subtract(v).mod(p).signum() == 0) ? r : null;
    }

    /**
     * NOT WORKING
     * Followed the "Exponentiation algorithm (elliptic curve version) on
     * powerpoint elliptic curve cryptography, slide 14 but implementation
     * is not working as expected.  The value of the BigInteger keeps growing
     * despite taking the modulus of each computation in the pointSum method.
     *
     * @param number that is multiplied to the point.
     * @param G      The point that is multiplied.
     * @return a computed point on Edward's curve.
     */
    public static ECPoint multiply(BigInteger number, ECPoint G) {

        ECPoint Y = G;
        for (BigInteger i = number; i.compareTo(BigInteger.ONE) > 0; i.subtract(BigInteger.ONE)) {
            Y = pointSum(Y, Y);
            if (Y.getX() == BigInteger.ONE) {

                Y = pointSum(Y, G);
            }
            else if(Y.getX() == BigInteger.ZERO && Y.getY() == BigInteger.ZERO) {

                return Y;
            }
        }
        return Y;
    }
}



