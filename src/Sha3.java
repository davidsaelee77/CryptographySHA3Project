import java.io.File;
import java.io.FileNotFoundException;
import java.math.BigDecimal;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Scanner;


public class Sha3 {
    /**
     * Stores sponge permutation rounds.
     */
    private static final int KECCAKF_ROUNDS = 24;
    /**
     * Stores byte size to manipulate security level call.
     */
    private static final int SIZE = 200;
    /**
     * Stores KMAC string, passed as a parameter in CSHAKE call. (KMAC function name bit string)
     */
    private static final String KMACSTRING = "KMAC";
    /**
     * Hard coded values to perform KMACXOF of arbitrary length.
     */
    private static final byte[] HARD_CODED_RIGHT_ENCODE = {(byte) 0x00, (byte) 0x01};
    /**
     * Initializes array to hold 200 bytes, stores data, length, and padding. (Sponge array)
     */
    private static byte[] byteArray = new byte[SIZE];
    /**
     * Flag to switch between KMAC or KMACXOF mode.
     */
    private boolean KMAC;
    /**
     * Flag to switch between KMAC or KMACXOF mode.
     */
    private boolean XOF_enabled;
    /**
     * Initializes data array used to store message byte data.
     */
    private byte[] dataArray = null;
    /**
     * Used for left encode or right encode bit strings.
     */
    private byte[] lengthArray = null;
    /**
     * Used to concatenate two different arrays.
     */
    private ByteBuffer byteBuffer = null;
    /**
     * Initializes long array to change byte array into 8 byte integers.
     * Used to replicate a C union.
     */
    private long[] longArray = new long[25];
    /**
     * Variable initialization to store mdlen(hashoutput in bytes), resize (compression), and pt (initializer).
     */
    private int mdlen, pt, resize, outputLen;
    /**
     * Flag to exit menu loop when user wants to quit.
     */
    private static boolean flag = true;
    /**
     * Variable to store the big integer 4.
     */
    private static BigInteger FOUR = BigInteger.valueOf(4);
    /**
     * Multiple string variables used as customization string for function parameters.
     */
    private static String ske = "SKE", ska = "SKA", pka = "PKA", pke = "PKE";
    /**
     * Multiple string variables used as customization string for function parameters.
     */
    private static String blank = "", d = "D", n = "N", k = "K", s = "S", t = "T", p = "P";

    /**
     * SHA3 default constructor.
     * Initializes an empty byte array for sponge manipulations.
     * Initializes state variables.
     */
    public Sha3() {
        Arrays.fill(byteArray, (byte) 0);
        mdlen = 32; // default for SHAKE256 (for SHA128 it would be 16)
        resize = SIZE - (2 * mdlen);
        pt = 0;
        KMAC = false;
        XOF_enabled = false;
    }

    /**
     * SHA3 constructor with key bit string and customizable string as parameters.  This method is used for KMAC256 which
     * will encode and pad the key to the specified security length.  It will then initiate the sponge
     * and call the compression function.
     *
     * @param K is a key bit string of any length, including zero. (32 bit example)
     * @param S is an optional customization bit string of any length, including zero. If no customization
     *          is desired, S is set to the empty string.
     */
    public Sha3(byte[] K, byte[] S) {
        this();
        dataArray = Arrays.copyOf(K, K.length);
        byte[] encodedKey = leftEncode(K.length << 3);
        encodedKey = bytePad(encodedKey, 136);
        init_c256Sponge(KMACSTRING.getBytes(), S);
        KMAC = true;
        sha3Update(encodedKey, encodedKey.length);
    }

    /**
     * SHA3 constructor with KMACXOF enabled.
     *
     * @param K              is a key bit string of any length, including zero. (32 bit example)
     * @param S              is an optional customization bit string of any length, including zero. If no customization
     *                       is desired, S is set to the empty string.
     * @param is_XOF_Enabled enables XOF mode where encoded length output is set to 0 for arbitrary length output.
     */
    public Sha3(byte[] K, byte[] S, boolean is_XOF_Enabled) {
        this(K, S);
        XOF_enabled = is_XOF_Enabled;
    }

    /**
     * CSHAKE256 function used to encode a message to NIST specifications.
     *
     * @param X is the main input bit string. It may be of any length, including zero.
     * @param L is an integer representing the requested output length in bits.
     * @param N is a function-name bit string, used by NIST to define functions based on cSHAKE.
     *          When no function other than cSHAKE is desired, N is set to the empty string. (N empty example)
     * @param S is a customization bit string. The user selects this string to define a variant of the (S = EMAIL SIGNATURE example)
     *          function. When no customization is desired, S is set to the empty string.
     * @return the encrypted hash value after looping numerous times in sponge.
     */
    public static byte[] SHAKE256(byte[] X, int L, byte[] N, byte[] S) {
        byte[] returnArray = new byte[L >>> 3]; // Ensures we have an array that is a multiple of 8.
        Sha3 sha = new Sha3();
        sha.init_c256Sponge(N, S); // Initializes the sponge with the provided N (EMPTY STRING) and S (EMAIL SIGNATURE) values.
        sha.sha3Update(X, X.length); //X is the input bit string (
        sha.shakeXOF();
        sha.shakeOut(returnArray, L >>> 3);

        return returnArray;
    }

    /**
     * KMACXOF256 function used to encode a message to NIST specifications.
     *
     * @param K is a key bit string of any length, including zero.
     * @param X is the main input bit string. It may be of any length, including zero.
     * @param L is an integer representing the requested output length in bits (512 example)
     * @param S is an optional customization bit string of any length, including zero. If no customization
     *          is desired, S is set to the empty string.
     * @return the encrypted hash value after looping numerous times in sponge.
     */
    public static byte[] KMACXOF256(byte[] K, byte[] X, int L, byte[] S) {
        byte[] returnArray = new byte[L >>> 3];
        Sha3 sha = new Sha3(K, S, true);
        if (sha.XOF_enabled) {
            sha.outputLen = 0;
        } else {
            sha.outputLen = L;
        }
        sha.sha3Update(X, X.length);
        sha.shakeXOF();
        sha.shakeOut(returnArray, L >>> 3);

        return returnArray;
    }

    /**
     * Method initializes the sponge and encodes the N and S values.
     *
     * @param N is a function-name bit string, used by NIST to define functions based on cSHAKE.
     *          When no function other than cSHAKE is desired, N is set to the empty string.
     * @param S is a customization bit string. The user selects this string to define a variant of the
     *          function. When no customization is desired, S is set to the empty string.
     */
    private void init_c256Sponge(byte[] N, byte[] S) {
        dataArray = Arrays.copyOf(N, N.length);
        N = leftEncode(N.length << 3); // Left encodes N value ("EMPTY STRING EXAMPLE")
        dataArray = Arrays.copyOf(S, S.length);
        S = leftEncode(S.length << 3); // Left encodes S value ("Email signature EXAMPLE")
        byteBuffer = ByteBuffer.allocate(N.length + S.length); //Allocates enough room for the two arrays.
        byteBuffer.put(N);
        byteBuffer.put(S, 0, S.length); // Places the two arrays into the byte buffer.
        byte[] prefix = byteBuffer.array();
        prefix = bytePad(prefix, 136);  // Pads the rest of the array with 0's until it reaches the necessary amount.
        sha3Update(prefix, prefix.length);
    }

    /**
     * Updates each block of the sponge with a new scrambled block of data.
     *
     * @param data   to be absorbed. ( 00, 01, 02, 03, 04 Example)
     * @param length the length of the data.
     * @return 0.
     */
    private int sha3Update(byte[] data, int length) {
        int j = pt;
        for (int i = 0; i < length; i++) {
            byteArray[j++] ^= data[i];
            if (j >= resize) {
                sha3Keccakf();
                j = 0;
            }
        }
        pt = j;

        return 0;
    }

    /**
     * KECCAKF compression function.
     */
    private void sha3Keccakf() {
        // constants
        final long[] rndc = new long[]
                {
                        0x0000000000000001L, 0x0000000000008082L, 0x800000000000808aL,
                        0x8000000080008000L, 0x000000000000808bL, 0x0000000080000001L,
                        0x8000000080008081L, 0x8000000000008009L, 0x000000000000008aL,
                        0x0000000000000088L, 0x0000000080008009L, 0x000000008000000aL,
                        0x000000008000808bL, 0x800000000000008bL, 0x8000000000008089L,
                        0x8000000000008003L, 0x8000000000008002L, 0x8000000000000080L,
                        0x000000000000800aL, 0x800000008000000aL, 0x8000000080008081L,
                        0x8000000000008080L, 0x0000000080000001L, 0x8000000080008008L
                };

        final int[] rotc = new int[]
                {
                        1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14,
                        27, 41, 56, 8, 25, 43, 62, 18, 39, 61, 20, 44
                };

        final int[] piln = new int[]
                {
                        10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4,
                        15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1
                };


        int i, j, r;
        long t;
        long[] bc = new long[5];
        updateLongArray();
        for (r = 0; r < KECCAKF_ROUNDS; r++) {
            // Theta
            for (i = 0; i < 5; i++) {
                bc[i] = longArray[i] ^ longArray[i + 5] ^ longArray[i + 10] ^ longArray[i + 15] ^ longArray[i + 20];
            }
            for (i = 0; i < 5; i++) {
                t = bc[(i + 4) % 5] ^ (rotl64(bc[(i + 1) % 5], 1));
                for (j = 0; j < 25; j += 5)
                    longArray[j + i] ^= t;
            }

            // Rho Pi
            t = longArray[1];
            for (i = 0; i < 24; i++) {
                j = piln[i];
                bc[0] = longArray[j];
                longArray[j] = rotl64(t, rotc[i]);
                t = bc[0];
            }

            // Chi
            for (j = 0; j < 25; j += 5) {
                for (i = 0; i < 5; i++) {
                    bc[i] = longArray[j + i];
                }
                for (i = 0; i < 5; i++) {
                    longArray[j + i] ^= (~bc[(i + 1) % 5]) & bc[(i + 2) % 5];
                }
            }

            // Iota
            longArray[0] ^= rndc[r];
        }
        updateByteArray();
    }

    /**
     * Method transfers data from byteArray to longArray.
     */
    private void updateLongArray() {
        byteBuffer = ByteBuffer.allocate(SIZE);
        byteBuffer.put(byteArray);

        // Change from Little Endian to Big Endian (and vice versa)
        byteBuffer.order(ByteOrder.LITTLE_ENDIAN);
        int j = 0;
        for (int i = 0; i < byteArray.length; i += 8) {
            longArray[j++] = byteBuffer.getLong(i);
        }
    }

    /**
     * Method transfers data from longArray to byteArray.
     */
    private void updateByteArray() {
        byteBuffer = ByteBuffer.allocate(SIZE);

        // Swap the bytes back to the original order.
        byteBuffer.order(ByteOrder.LITTLE_ENDIAN);
        int j = 0;
        for (int i = 0; i < longArray.length; i++) {
            byteBuffer.putLong(j, longArray[i]);
            j += 8;
        }
        byteArray = byteBuffer.array();
    }

    /**
     * Method determines if KMACXOF mode is enabled.  If XOF is true then
     * the hard coded rightEncode values will be used to create a
     * encoded hash output of an arbitrary length.
     */
    private void shakeXOF() {
        byte[] encodedArray = null;

        if (KMAC) {
            if (XOF_enabled) {
                encodedArray = HARD_CODED_RIGHT_ENCODE;
            }
         /*   else
            {
                ByteBuffer dataBuffer = ByteBuffer.allocate(Short.SIZE/Byte.SIZE);
                dataBuffer.putShort((short)outputLen);
                byte [] data = dataBuffer.array();

                dataArray = Arrays.copyOf(data, data.length);
                encodedArray = rightEncode(data.length);
            }*/

            sha3Update(encodedArray, encodedArray.length);
        }
        byteArray[pt] ^= (byte) 0x04;
        byteArray[resize - 1] ^= (byte) 0x80;
        sha3Keccakf();
        pt = 0;
    }

    /**
     * Method produces a block of encoded data from sponge.
     *
     * @param out    encoded hash data block.
     * @param length encoded hash data length.
     */
    private void shakeOut(byte[] out, int length) {
        // Compression function.
        int j = pt;
        for (int i = 0; i < length; i++) {
            if (j >= resize) {
                sha3Keccakf();
                j = 0;
            }
            out[i] = byteArray[j++];
        }
        pt = j;
    }

    /**
     * Bit shift method used in KECCACKF manipulations.
     *
     * @param x integer value.
     * @param y integer value.
     * @return integer value bit shifted to specified length.
     */
    private long rotl64(long x, int y) {
        return (x << y) | (x >>> (64 - y));
    }

    /**
     * THIS CODE WAS INSPIRED BY PROFESSOR BARRETO'S LEFT ENCODE IMPLEMENTATION.
     * <p>
     * Method sets up the size of the lengthArray based on the value of encodeNum.
     * EncodedNum can be dataArray's bitLength of data or 136 in order to bypass Java's lack of unsigned data types.
     *
     * @param encodeNum bit length of data or 136.
     * @return an encoded byte string with the size of the data prepended at the first index, followed
     * by the length.
     */
    private byte[] leftEncode(long encodeNum) {
        int n = 1;
        while ((1 << (8 * n)) <= encodeNum) {
            n++;
        }
        lengthArray = new byte[n + 1];

        // Populate lengthArray
        for (int i = n; i > 0; i--) {
            lengthArray[i] = (byte) (encodeNum & 0xFF);
            encodeNum >>>= 8;
        }

        // Populate size of lengthArray in lengthArray[0]
        lengthArray[0] = (byte) n;
        ByteBuffer encoder = ByteBuffer.allocate(lengthArray.length + dataArray.length);

        // Combine lengthArray and dataArray.
        encoder.put(lengthArray);
        for (int i = 0; i < dataArray.length; i++)
            encoder.put(i + lengthArray.length, dataArray[i]);
        byte[] leftEncodedByteString = encoder.array();

        return leftEncodedByteString;
    }

    /**
     *THIS METHOD DOES NOT WORK CORRECTLY IF THE
     * ENCODED OUTPUT LENGTH IS 0.  DOES NOT WORK FOR
     * KMACXOF.  THEREFORE, WE MUST USE THE HARDCODED RIGHT ENCODE
     * INITIALIZED IN THE FIELD. UNSURE HOW TO HANDLE
     * NEGATIVE VALUES.  JAVA FORCES MORE BYTES THEN NECESSARY.
     */
  /*  private byte[] rightEncode(long encodeNum)
    {

        int n = 1;
        while ((1 << (8*n)) <= encodeNum)
        {
            n++;
        }
        lengthArray = new byte[n];

        // Populate lengthArray
        for (int i = 0; i < n; i++)
        {
            lengthArray[i] = (byte)(encodeNum & 0xFF);
            encodeNum >>>= 8;
        }
        ByteBuffer encoder = ByteBuffer.allocate(lengthArray.length + dataArray.length);

        // Combine dataArray and lengthArray.
        encoder.put(dataArray);
        for (int i = 0; i < lengthArray.length; i++)
            encoder.put(i + dataArray.length, lengthArray[i]);
        byte [] rightEncodedByteString = encoder.array();

        return rightEncodedByteString;

    }*/

    /**
     * Combines with left encode, then pads
     * 0's to specified length.
     *
     * @param encodedArray of encoded data value.
     * @param encodeInt    of encoded bit length data.
     * @return an array consisting of the data size, length, actual data and padded with zeros for specified length.
     */
    private byte[] bytePad(byte[] encodedArray, int encodeInt) {

        dataArray = encodedArray;
        byte[] array = leftEncode(encodeInt);
        if (array.length % encodeInt == 0)
            return array;
        else {
            int padCount = 0;
            int length = array.length;

            while (length % encodeInt != 0) {
                padCount++;
                length++;
            }
            ByteBuffer padBuffer = ByteBuffer.allocate(padCount);
            byte[] padArray = padBuffer.array();
            ByteBuffer encoder = ByteBuffer.allocate(array.length + padArray.length);

            // Combine array and padArray.
            encoder.put(array);
            for (int i = 0; i < padArray.length; i++)
                encoder.put(i + array.length, padArray[i]);
            array = encoder.array();
        }

        return array;
    }

    /**
     * User interface used to call encryption/decryption methods.
     *
     * @param args java standard for command line
     * @throws FileNotFoundException error checking to determine if file is present.
     */
    public static void main(String[] args) throws FileNotFoundException {

        Scanner userInput = new Scanner(System.in);
        while (flag == true) {
            System.out.println("********************************************************************");
            System.out.println("Please select an option below: ");
            System.out.println("*******************************************************************");
            System.out.println("Enter 1: To compute a plain cryptographic hash from a file: ");
            System.out.println("Enter 2: To input your own message to compute a cryptographic hash: ");
            System.out.println("Enter 3: To encrypt and decrypt a given passphrase: ");
            System.out.println("Enter 4: To encrypt and decrypt a elliptic curve key pair: ");
            System.out.println("Enter 5: To generate and verify a digital signature: ");
            System.out.println("Enter 6: Quit");
            System.out.println("*******************************************************************");
            int option = userInput.nextInt();

            //Very minimal user error checking.
            if (option <= 0 || option > 6) {
                System.out.println("You have selected an invalid option.  Please select again: ");
            } else {
                switch (option) {
                    case 1:
                        System.out.println("Please select 0 for CSHAKE256 mode or 1 for KMACXOF256 mode.");
                        int fileMode = userInput.nextInt();
                        readFile(fileMode);
                        break;
                    case 2:
                        System.out.println("Please select 0 for CSHAKE256 mode or 1 for KMACXOF256 mode.");
                        int userMode = userInput.nextInt();
                        userInput(userMode);
                        break;
                    case 3:
                        encryptAndDecryptSymmetric();
                        break;
                    //Case 4, and 5 are not working properly due to incorrect implementation
                    //of point scalar multiplication or other various factors.
                    case 4:
                        encryptAndDecryptECurve();
                        break;
                    case 5:
                        generateAndVerifySignature();
                        break;
                    case 6:
                        quit();
                        break;
                }
            }
        }
        return;

    }

    /**
     * Parses text file line by line and encrypts data in cSHAKE256 or KMACXOF256 mode.
     * Prints an encrypted array hash in both decimal and hexadecimal format.
     *
     * @param mode option to change between cSHAKE or KMAC
     * @throws FileNotFoundException error checking to determine if file is present.
     */
    public static void readFile(int mode) throws FileNotFoundException {

        int modeSelect = mode;
        String fileData = "";
        Scanner in = new Scanner(new File(new String("test.txt")));
        while (in.hasNextLine()) {
            fileData = fileData.concat(in.nextLine());
        }
        byte[] scannerByteArray = fileData.getBytes();
        if (modeSelect == 0) {
            byte[] encodedFileSHAKE = Sha3.SHAKE256(scannerByteArray, scannerByteArray.length, blank.getBytes(), blank.getBytes());
            System.out.println(Arrays.toString(encodedFileSHAKE));
            System.out.println(bytesToHexString(encodedFileSHAKE));
        } else if (modeSelect == 1) {
            byte[] encodedFileKMAC = Sha3.KMACXOF256(blank.getBytes(), scannerByteArray, 512, d.getBytes());
            System.out.println(Arrays.toString(encodedFileKMAC));
            System.out.println(bytesToHexString(encodedFileKMAC));
        }
    }

    /**
     * Takes user input to generate an encrypted cryptographic hash that is user specific.
     * Prints an encrypted array hash in both decimal and hexadecimal format.
     *
     * @param mode option to change between cSHAKE or KMAC
     */
    public static void userInput(int mode) {

        int modeSelect = mode;
        Scanner consoleInput = new Scanner(System.in).useDelimiter("\\n");
        System.out.println("Please enter a key, it can be any length including 0");
        String key = consoleInput.next();
        System.out.println("Please enter a message, it can be any length including 0");
        String message = consoleInput.next();
        System.out.println("Please enter the security length: 128, 256, 512 or 1024");
        int length = consoleInput.nextInt();
        System.out.println("Please enter an optional customization string: ");
        String custom = consoleInput.next();

        if (modeSelect == 0) {
            byte[] encodedFileSHAKE = Sha3.SHAKE256(message.getBytes(), message.getBytes().length, blank.getBytes(), blank.getBytes());
            System.out.println(Arrays.toString(encodedFileSHAKE));
            System.out.println(bytesToHexString(encodedFileSHAKE));
        } else if (modeSelect == 1) {
            byte[] encodedUserMessage = Sha3.KMACXOF256(key.getBytes(), message.getBytes(), length, custom.getBytes());
            System.out.println(Arrays.toString(encodedUserMessage));
            System.out.println(bytesToHexString(encodedUserMessage));
        }
    }

    /**
     * This method will take input from the user, encrypt the key and passphrase,
     * and print out the decrypted message. The encrypted array hash in both decimal
     * hexadecimal format and the message is in string format.  THe method
     * will compare the two authentication tags together to determine
     * if the message was successful decrypted without being altered
     * during transmission.
     */
    public static void encryptAndDecryptSymmetric() {

        Scanner input = new Scanner(System.in).useDelimiter("\\n");

        //z <-- Random(512);
        SecureRandom random = new SecureRandom();
        byte[] z = random.generateSeed(512 >> 3);
        System.out.println("Please enter a passphrase: ");
        String pw = input.nextLine(); //"password";

        //(ke || ka) <-- KMACXOF256(z || pw, “”, 1024, “S”)
        byte[] key = new byte[z.length + pw.getBytes().length];
        System.arraycopy(z, 0, key, 0, z.length);
        System.arraycopy(pw.getBytes(), 0, key, z.length, pw.getBytes().length);
        System.out.println("Please enter the message to be encrypted: ");
        String m = input.nextLine();
        byte[] message = m.getBytes();
        byte[] keka = Sha3.KMACXOF256(key, blank.getBytes(), 1024, s.getBytes());

        // Encryption
        //c <-- KMACXOF256(ke, “”, |m|, “SKE”) XOR m
        byte[] ke = Arrays.copyOfRange(keka, 0, keka.length / 2);
        byte[] ka = Arrays.copyOfRange(keka, keka.length / 2, keka.length);
        byte[] sp = Sha3.KMACXOF256(ke, blank.getBytes(), message.length << 3, ske.getBytes());
        byte c[] = new byte[message.length];
        for (int i = 0; i < message.length; i++) {
            c[i] = (byte) (message[i] ^ sp[i]);
        }

        //t <-- KMACXOF256(ka, m, 512, “SKA”)
        byte[] t = Sha3.KMACXOF256(ka, message, 512, ska.getBytes());
        System.out.println("Below is the encrypted message: ");
        System.out.println(Arrays.toString(c));
        System.out.println("Below is the encrypted HEX message: ");
        System.out.println(bytesToHexString(c));

        // Decryption
        //(ke || ka) <-- KMACXOF256(z || pw, “”, 1024, “S”)
        //m <-- KMACXOF256(ke, “”, |c|, “SKE”) XOR c
        byte[] sp2 = Sha3.KMACXOF256(ke, blank.getBytes(), c.length << 3, ske.getBytes());
        byte[] message2 = new byte[c.length];
        for (int i = 0; i < message.length;
             i++) {
            message2[i] = (byte) (c[i] ^ sp2[i]);
        }
        System.out.println("Below is the decrypted message: ");
        System.out.println(Arrays.toString(message2));
        System.out.println("Below is the decrypted HEX message: ");
        System.out.println(bytesToHexString(message2));

        //t’ <-- KMACXOF256(ka, m, 512, “SKA”)
        byte[] t2 = Sha3.KMACXOF256(ka, message2, 512, ska.getBytes());
        System.out.println("Below is the authentication tag: ");

        System.out.println(Arrays.toString(t));
        System.out.println("Below is the authentication tag in HEX format: ");
        System.out.println(bytesToHexString(t));
        if (Arrays.equals(t, t2))
            System.out.println("The encryption and decryption is correct: " + new String(message2));
        else
            System.out.println("The encryption and decryption is INCORRECT!!!");
    }

    /**
     * MAYBE THIS WORKS CORRECTLY NOW?  UNSURE... MORE TESTING NEEDS TO BE DONE
     * BEFORE WE DRAW CONCLUSIONS.  MADE SOME CHANGES IN THE ECPOINT CLASS BUT
     * UNSURE IF THIS IS ACTUALLY VALID OUTPUT.
     *
     * This method is not presently working.  It should take user input and encrypt the key
     * and message then construct an elliptic curve to encrypt and then decrypt the message.
     * However, there is an issue with the implementation of the multiply method in the ECPoint
     * class that prevents this method from working correctly.  There may be other factors that
     * are contributing to the incorrect implementation, but we know for sure that the multiply
     * method is wrong.
     */
    public static void encryptAndDecryptECurve() {

        Scanner input = new Scanner(System.in).useDelimiter("\\n");
        System.out.println("Please enter message to be encrypted: ");
        String m = input.nextLine();
        byte[] mArray = m.getBytes();
        System.out.println("Please enter a passphrase: ");
        String pw = input.nextLine();

        //s <-- KMACXOF256(pw, “”, 512, “K”); s <-- 4s
        byte[] spongeS = Sha3.KMACXOF256(pw.getBytes(), blank.getBytes(), 512, k.getBytes());
        byte[] spongeSConcat = prependByte(spongeS);
        BigInteger spongeSBI = new BigInteger(spongeSConcat);

        //V <-- s*G
        ECPoint G = new ECPoint(FOUR, FOUR);
        BigInteger fourS = spongeSBI.multiply(FOUR);
        ECPoint V = ECPoint.multiply(fourS, G);

        //KEY PAIR ENCRYPTION
        //k <-- Random(512);
        SecureRandom random = new SecureRandom();
        byte[] kArray = random.generateSeed(512 >> 3);
        byte[] kArrayConcat = prependByte(kArray);

        //k <-- 4k;
        BigInteger randomK = new BigInteger(kArrayConcat);
        BigInteger fourK = FOUR.multiply(randomK);

        //W <-- k*V; Z <-- k*G;
        ECPoint W = ECPoint.multiply(fourK, V);
        ECPoint Z = ECPoint.multiply(fourK, G);

        //(ke || ka) <-- KMACXOF256(Wx, “”, 1024, “P”)
        byte[] Wx = W.getX().toByteArray();
        byte[] keka = Sha3.KMACXOF256(Wx, blank.getBytes(), 1024, p.getBytes());
        byte[] ke = Arrays.copyOfRange(keka, 0, keka.length / 2);
        byte[] ka = Arrays.copyOfRange(keka, keka.length / 2, keka.length);

        //c <-- KMACXOF256(ke, “”, |m|, “PKE”) XOR m
        byte[] pairSponge = Sha3.KMACXOF256(ke, blank.getBytes(), mArray.length << 3, pke.getBytes());
        byte[] cPair = new byte[mArray.length];
        for (int i = 0; i < mArray.length; i++) {
            cPair[i] = (byte) (mArray[i] ^ pairSponge[i]);
        }
        System.out.println("Below is the encrypted message: ");
        System.out.println(Arrays.toString(cPair));
        System.out.println("Below is the encrypted HEX message: ");
        System.out.println(bytesToHexString(cPair));

        //t <-- KMACXOF256(ka, m, 512, “PKA”);
        byte[] tPair = Sha3.KMACXOF256(ka, mArray, 512, pka.getBytes());

        //KEY PAIR DECRYPTION
        //s <-- KMACXOF256(pw, “”, 512, “K”);
        byte[] sPair = Sha3.KMACXOF256(pw.getBytes(), blank.getBytes(), 512, k.getBytes());
        byte[] sPairConcat = prependByte(sPair);

        //s <-- 4s;
        BigInteger sBI = new BigInteger(sPairConcat);
        BigInteger sPairFour = sBI.multiply(fourS);

        //W <-- s*Z;
        ECPoint WDecrypt = ECPoint.multiply(sPairFour, Z);
        byte[] WxDecrypt = WDecrypt.getX().toByteArray();

        //(ke || ka) <-- KMACXOF256(Wx, “”, 1024, “P”)
        byte[] kekaDecrypt = Sha3.KMACXOF256(WxDecrypt, blank.getBytes(), 1024, p.getBytes());
        byte[] keDecrypt = Arrays.copyOfRange(kekaDecrypt, 0, kekaDecrypt.length / 2);
        byte[] kaDecrypt = Arrays.copyOfRange(kekaDecrypt, kekaDecrypt.length / 2, kekaDecrypt.length);

        //m <-- KMACXOF256(ke, “”, |c|, “PKE”) XOR c
        byte[] mDecryptSponge = Sha3.KMACXOF256(keDecrypt, blank.getBytes(), cPair.length << 3, pke.getBytes());
        byte[] mDecryptPair = new byte[mDecryptSponge.length];
        for (int i = 0; i < cPair.length; i++) {
            mDecryptPair[i] = (byte) (cPair[i] ^ mDecryptSponge[i]);
        }
        System.out.println("Below is the decrypted message: ");
        System.out.println(Arrays.toString(mDecryptPair));
        System.out.println("Below is the decrypted HEX message: ");
        System.out.println(bytesToHexString(mDecryptPair));

        //t’ <-- KMACXOF256(ka, m, 512, “PKA”)
        byte[] t2Pair = Sha3.KMACXOF256(kaDecrypt, mArray, 512, pka.getBytes());
        System.out.println("Below is the authentication tag: ");
        System.out.println(Arrays.toString(tPair));
        System.out.println("Below is the authentication tag in HEX form: ");
        System.out.println(bytesToHexString(tPair));

        //accept if, and only if, t’ = t
        if (Arrays.equals(tPair, t2Pair)) {
            System.out.println("The encryption and decryption is correct: " + new String(mDecryptPair));
        } else {
            System.out.println("The encryption and decryption is INCORRECT!!!");
        }
    }

    /**
     * SAME ISSUE AS ABOVE:
     * This method is not presently working.  It should take user input and encrypt the key
     * and message then construct an elliptic curve to encrypt and then decrypt the message.
     * However, there is an issue with the implementation of the multiply method in the ECPoint
     * class that prevents this method from working correctly.  There may be other factors that
     * are contributing to the incorrect implementation, but we know for sure that the multiply
     * method is wrong.
     */
    public static void generateAndVerifySignature() {

        //Generate Signature:
        Scanner input = new Scanner(System.in).useDelimiter("\\n");
        BigInteger largeNumber = new BigInteger("337554763258501705789107630418782636071904961214051226618635150085779108655765");
        double r = Math.pow(2, 519);
        BigDecimal decimalR = new BigDecimal(r);
        BigInteger rBI = decimalR.toBigInteger().subtract(largeNumber);
        System.out.println("Please enter a passphrase: ");
        String pw = input.nextLine();
        System.out.println("Please enter a signature: ");
        String m = input.nextLine();
        byte[] mArray = m.getBytes();

        //s <-- KMACXOF256(pw, “”, 512, “K”);
        byte[] s = Sha3.KMACXOF256(pw.getBytes(), blank.getBytes(), 512, k.getBytes());
        byte[] sConcat = prependByte(s);

        //s <--4s;
        BigInteger sBI = new BigInteger(sConcat);
        BigInteger fourS = FOUR.multiply(sBI);
        byte[] fourSArray = fourS.toByteArray();

        //k <--KMACXOF256(s, m, 512, “N”);
        byte[] k = Sha3.KMACXOF256(fourSArray, mArray, 512, n.getBytes());
        byte[] kConcat = prependByte(k);

        //k <-- 4k;
        BigInteger kBI = new BigInteger(kConcat);
        BigInteger fourK = FOUR.multiply(kBI);

        //U <-- k*G;
        ECPoint G = new ECPoint(FOUR, FOUR);
        ECPoint U = ECPoint.multiply(fourK, G);

        //h <-- KMACXOF256(Ux, m, 512, “T”);
        byte[] Ux = U.getX().toByteArray();
        byte[] h = Sha3.KMACXOF256(Ux, mArray, 512, t.getBytes());

        //z <--(k – hs) mod r
        BigInteger hBI = new BigInteger(h);
        byte[] hs = multiplyByteArray(h, s);
        byte[] kSubHS = subtractByteArray(k, hs);

        //σ <--(h, z)
        BigInteger z = new BigInteger(kSubHS).mod(rBI);
        ECPoint signatureSigma = new ECPoint(hBI, z);

        //Verify Signature:
        //U <-- z*G + h*V
        ECPoint V = ECPoint.multiply(sBI, G);
        ECPoint zG = ECPoint.multiply(z, G);
        ECPoint hV = ECPoint.multiply(hBI, V);
        ECPoint UVerify = ECPoint.pointSum(zG, hV);
        byte[] UxVerify = UVerify.getX().toByteArray();
        byte[] hVerify = Sha3.KMACXOF256(UxVerify, mArray, 512, t.getBytes());

        //accept if, and only if, KMACXOF256(Ux, m, 512, “T”) = h;
        if (Arrays.equals(h, hVerify)) {
            System.out.println("The signature is a valid signature!");
        } else {
            System.out.println("The signature is invalid, it is INCORRECT!!!");
        }
    }

    /**
     * Terminates program.
     */
    public static void quit() {

        flag = false;
        System.out.println("Program has terminated");
    }

    /**
     * A helper function that multiplies two byte arrays.
     *
     * @param a byte array to be multiplied.
     * @param b byte array to be multiplied.
     * @return a new byte array of a x b.
     */
    public static byte[] multiplyByteArray(byte[] a, byte[] b) {

        int aLen = a.length;
        int bLen = b.length;
        int lengthOfNewByteArray = 0;
        if (aLen > bLen) {
            lengthOfNewByteArray = aLen;
        } else {
            lengthOfNewByteArray = bLen;
        }
        byte[] returnArray = new byte[lengthOfNewByteArray];
        int count = 0;
        while (count < aLen && count < bLen) {
            returnArray[count] = (byte) (a[count] * b[count]);
            count++;
        }
        if (aLen > bLen) {
            returnArray[count] = (byte) (a[count]);
        } else if (bLen > aLen) {
            returnArray[count] = (byte) (b[count]);
        }
        return returnArray;
    }

    /**
     * Helper method that subtracts two byte arrays.
     *
     * @param a byte array to be subtracted.
     * @param b byte array to be subtracted.
     * @return a new byte array of either a - b or b - a.
     */
    public static byte[] subtractByteArray(byte[] a, byte[] b) {

        int aLen = a.length;
        int bLen = b.length;
        int lengthOfNewByteArray = 0;
        if (aLen > bLen) {
            lengthOfNewByteArray = aLen;
        } else {
            lengthOfNewByteArray = bLen;
        }
        byte[] returnArray = new byte[lengthOfNewByteArray];
        int count = 0;
        while (count < aLen && count < bLen) {
            if (aLen > bLen) {
                returnArray[count] = (byte) (a[count] - b[count]);
                count++;
            } else if (bLen > aLen) {
                returnArray[count] = (byte) (b[count] - a[count]);
                count++;
            }
        }
        if (aLen > bLen) {
            returnArray[count] = (byte) (a[count]);
        } else if (bLen > aLen) {
            returnArray[count] = (byte) (b[count]);
        }
        return returnArray;
    }

    /**
     * Converts a decimal byte array to it's hexadecimal equivalent.
     *
     * @param bytes a byte array to be converted.
     * @return a new byte array with hexadecimal elements.
     */
    public static String bytesToHexString(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x ", b & 0xff).toUpperCase());
        }
        return sb.toString();
    }

    /**
     * Prepends a 0x00 byte to the array that is passed in.  (To force JAVA
     * to recognize the array as a positive number when multiplying with a big integer).
     *
     * @param array that needs to be prepended with a 0 byte.
     * @return a new array with a 0 byte prepended to the front.
     */
    public static byte[] prependByte(byte[] array) {

        byte[] index1 = new byte[1];
        index1[0] = (byte) 0x00;
        ByteBuffer concat = ByteBuffer.allocate(index1.length + array.length);
        concat.put(index1);
        concat.put(array, 0, array.length);
        byte[] concatArray = concat.array();
        return concatArray;
    }
}











