import java.math.BigInteger;
import java.security.spec.ECPoint;
import java.security.spec.EllipticCurve;

public class test {


    public static void main(String[] args) {



        /* CSHAKE256 TEST

        String str = "The bytepad(X, w) function prepends an encoding of the integer w to an input string X, then pads "+
                "the result with zeros until it is a byte string whose length in bytes is a multiple of w. In general, " +
                "bytepad is intended to be used on encoded strings—the byte string bytepad(encode_string(S), w) "+
                "can be parsed unambiguously from its beginning, whereas bytepad does not provide "+
                "unambiguous padding for all input strings.";

        byte [] array = str.getBytes();
        Sha3 sha = new Sha3();
        sha.sha3Update(array, array.length);*/


//PART 1: CRYPTO HASH DIGEST OF H:

/*      String blank = "";
        String m = "David";
        String d = "D";
        String _t = "T";
        String pw = "password";

        byte[] h = Sha3.KMACXOF256(blank.getBytes(), m.getBytes(), 512, d.getBytes());

        // PART 1: MESSAGE AUTHENTICATION CODE:

        byte[] t = Sha3.KMACXOF256(pw.getBytes(), m.getBytes(), 512, _t.getBytes());*/


/*       //KMACXOF256 TEST -- NO FILE READ OR USER INPUT IMPLEMENTED YET

        byte [] key = new byte[32];
        for (int i = 0; i < key.length; i++) {
            key[i] = (byte) (i + 0x40);
        }

        int x = 66051; // == 00 01 02 03 in HEX
        ByteBuffer dataBuffer = ByteBuffer.allocate(Integer.SIZE/Byte.SIZE);
        dataBuffer.putInt(x);
        byte [] data = dataBuffer.array();

        String taggedApp = "My Tagged Application";

//        String str = "";
//        String emailSign = "Email Signature";

        byte [] outVal = Sha3.KMACXOF256(key, data, 512, taggedApp.getBytes());*/


/*        //PART 2 SYMMETRIC ENCRYPT/DECRYPT
        SecureRandom random = new SecureRandom();
        byte[] z = random.generateSeed(512 >> 3);

        String pw = "password";

        byte[] key = new byte[z.length + pw.getBytes().length];

        System.arraycopy(z, 0, key, 0, z.length);
        System.arraycopy(pw.getBytes(), 0, key, z.length, pw.getBytes().length);

        String blank = "";
        String m = "David";
        String s = "S";
        String ske = "SKE";
        String ska = "SKA";

        Sha3 sha = new Sha3();

        byte[] message = m.getBytes();

        byte[] keka = Sha3.KMACXOF256(key, blank.getBytes(), 1024, s.getBytes());

        // Encryption
        byte[] ke = Arrays.copyOfRange(keka, 0, keka.length / 2);

        byte[] ka = Arrays.copyOfRange(keka, keka.length / 2, keka.length);

        byte[] sp = Sha3.KMACXOF256(ke, blank.getBytes(), message.length << 3,
                ske.getBytes());

        byte c[] = new byte[message.length];

        for (int i = 0; i < message.length; i++) {
            c[i] = (byte) (message[i] ^ sp[i]);
        }

        byte[] t = Sha3.KMACXOF256(ka, message, 512, ska.getBytes());

        // Decryption
        byte[] sp2 = Sha3.KMACXOF256(ke, blank.getBytes(), c.length << 3, ske.getBytes());

        byte[] message2 = new byte[c.length];
        for (int i = 0; i < message.length;
             i++) {
            message2[i] = (byte) (c[i] ^ sp2[i]);
        }

        byte[] t2 = Sha3.KMACXOF256(ka, message2, 512, ska.getBytes());

        if (Arrays.equals(t, t2))
            System.out.println("The encryption and decryption is correct: " + new String(message2));
        else
            System.out.println("The encryption and decryption is INCORRECT!!!");*/


//PART 3 SCHNORR/ECDHIES KEY PAIR

    /*String m = "Patrick";
    byte[] mArray = m.getBytes();
    String pw = "pw";
    String k = "K";
    String blank = "";
    String p = "P";
    String pke = "PKE";
    String pka = "PKA";
    int n = 4;

    byte[] spongeS = Sha3.KMACXOF256(pw.getBytes(), blank.getBytes(), 512, k.getBytes());
    BigInteger signatureBI = new BigInteger(spongeS);
    BigInteger four = BigInteger.valueOf(n);
    BigInteger fourS = signatureBI.multiply(four);
    byte[] s = fourS.toByteArray();

    ECPoint G = new ECPoint(four, four);

    ECPoint V = G.multiply(fourS);

//PART 3 ENCRYPTING UNDER SCHNORR/ECDHIES public key V:


    //KEY PAIR ENCRYPTION
    SecureRandom random = new SecureRandom();
    byte[] kArray = random.generateSeed(512 >> 3);

    // int num = 4;

    BigInteger randomK = new BigInteger(k);
    // BigInteger four = BigInteger.valueOf(n);

    BigInteger fourK = four.multiply(randomK);

    ECPoint W = V.multiply(fourK);

    ECPoint Z = G.multiply(fourK);

    String Wx = W.getX().toString();

    byte[] keka = Sha3.KMACXOF256(Wx.getBytes(), blank.getBytes(), 1024, p.getBytes());


    byte[] ke = Arrays.copyOfRange(keka, 0, keka.length / 2);

    byte[] ka = Arrays.copyOfRange(keka, keka.length / 2, keka.length);


    byte[] pairSponge = Sha3.KMACXOF256(ke, blank.getBytes(), mArray.length, pke.getBytes());


    byte cPair[] = new byte[mArray.length];


        for (int i = 0; i < mArray.length; i++) {

        cPair[i] = (byte) (mArray[i] ^ pairSponge[i]);
        }

        byte[] tPair = Sha3.KMACXOF256(ka, mArray, 512, pka.getBytes());


        //KEY PAIR DECRYPTION

        byte[] sPair = Sha3.KMACXOF256(pw.getBytes(), blank.getBytes(), 512, k.getBytes());

        BigInteger sBI = new BigInteger(sPair);

        BigInteger sPairFour = sBI.multiply(fourS);

        ECPoint WDecrypt = Z.multiply(sPairFour);

        String WxDecrypt = WDecrypt.getX().toString();

        byte[] kekaDecrypt = Sha3.KMACXOF256(WxDecrypt.getBytes(), blank.getBytes(), 1024, p.getBytes());

        byte[] keDecrypt = Arrays.copyOfRange(keka, 0, kekaDecrypt.length / 2);

        byte[] kaDecrypt = Arrays.copyOfRange(keka, kekaDecrypt.length / 2, kekaDecrypt.length);

        byte[] mDecryptSponge = Sha3.KMACXOF256(keDecrypt, blank.getBytes(), cPair.length, pke.getBytes());

        byte[] mDecryptPair = new byte[mDecryptSponge.length];

        for (int i = 0; i < mArray.length; i++) {

        mDecryptPair[i] = (byte) (cPair[i] ^ mDecryptSponge[i]);
        }

        byte[] t2Pair = Sha3.KMACXOF256(kaDecrypt, mArray, 512, pka.getBytes());


        if (Arrays.equals(tPair, t2Pair)) {
        System.out.println("The encryption and decryption is correct: " + new String(mDecryptPair));
        } else {
        System.out.println("The encryption and decryption is INCORRECT!!!");
        }*/


/*    //Part 5: Generating signatures:

        //Generate Signature:

        BigInteger largeNumber = new BigInteger("337554763258501705789107630418782636071904961214051226618635150085779108655765");
        double r = Math.pow(2, 519);
        BigDecimal decimalR = new BigDecimal(r);
        BigInteger rBI = decimalR.toBigInteger().subtract(largeNumber);

        String n = "N";
        String t = "T";
        String pw = "pw";
        String m = "David";

        byte[] mArray = m.getBytes();

        byte[] s = Sha3.KMACXOF256(pw.getBytes(), blank.getBytes(), 512, k.getBytes());
        byte[] sConcat = prependByte(s);
        BigInteger sBI = new BigInteger(sConcat);
        BigInteger fourS = FOUR.multiply(sBI);

        byte[] kArray = Sha3.KMACXOF256(s, mArray, 512, n.getBytes());
        byte[] kConcat = prependByte(kArray);
        BigInteger kBI = new BigInteger(kConcat);
        BigInteger fourK = FOUR.multiply(kBI);

        ECPoint G = new ECPoint(FOUR, FOUR);

        ECPoint U = G.multiply(fourK, G);

        byte[] Ux = U.getX().toByteArray();

        byte[] h = Sha3.KMACXOF256(Ux, mArray, 512, t.getBytes());

        BigInteger hBI = new BigInteger(h);

        byte[] hs = multiplyByteArray(h, s);

        byte[] kSubHS = subtractByteArray(k, hs);

        BigInteger z = new BigInteger(kSubHS).mod(rBI);

        ECPoint signatureSigma = new ECPoint(hBI, z);

Part 5: Verifying signature:

        //Verify Signature:
        ECPoint V = G.multiply(sBI, G);

        ECPoint zG = G.multiply(z, G);
        ECPoint hV = V.multiply(hBI, V);

        ECPoint UVerify = zG.pointSum(hV);


        byte[] UxVerify = UVerify.getX().toByteArray();

        byte[] hVerify = Sha3.KMACXOF256(UxVerify, mArray, 512, t.getBytes());

        if (Arrays.equals(h, hVerify)) {
            System.out.println("The signature is a valid signature!");
        } else {
            System.out.println("The signature is invalid, it is INCORRECT!!!");
        }*/

        return;

    }
}
