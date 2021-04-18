import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;

public class Proto {
    public static final int nonceLength = 64;
    public static final int rsaKeyLength = 1024;
    public static final int rsaEncryptionBatchLimit = rsaKeyLength / 8 - 11;
    public static final int rsaDecryptionBatchLimit = rsaKeyLength / 8;
    public static final int signedDigestLength = rsaKeyLength / 8;
    public static final String keyGenAlgo = "RSA";
    public static final String digestAlgo = "MD5";
    public static final String certificateType = "X.509";
    public static final String cipherAsymmetricAlgo = "RSA/ECB/PKCS1Padding";
    public static final String cipherSymmetricAlgo = "AES/ECB/PKCS5Padding";

    public static class pType {
        public static final int plainMsg = 0;
        public static final int encryptedMsg = 1;
        public static final int filename = 2;
        public static final int file = 3;
        public static final int cert = 99;
        public static final int nonce = 98;
        public static final int pubKey = 97;
        public static final int sessionKey = 96;
    }

    private static byte[][] splitBytes(final byte[] data, final int chunkSize) {
        // Curtsey of https://stackoverflow.com/a/32179121
        final int length = data.length;
        final byte[][] dest = new byte[(length + chunkSize - 1) / chunkSize][];
        int destIndex = 0;
        int stopIndex = 0;

        for (int startIndex = 0; startIndex + chunkSize <= length; startIndex += chunkSize) {
            stopIndex += chunkSize;
            dest[destIndex++] = Arrays.copyOfRange(data, startIndex, stopIndex);
        }

        if (stopIndex < length)
            dest[destIndex] = Arrays.copyOfRange(data, stopIndex, length);

        return dest;
    }

    public static byte[][] splitBytesForEncryption(final byte[] data) {
        return splitBytes(data, rsaEncryptionBatchLimit);
    }

    public static byte[][] splitBytesForDecryption(final byte[] data) {
        return splitBytes(data, rsaDecryptionBatchLimit);
    }

    public static byte[] concatBytes(byte[][] data) throws IOException {
        ByteArrayOutputStream byteStream = new ByteArrayOutputStream();
        for (byte[] batch : data) {
            byteStream.write(batch);
        }
        return byteStream.toByteArray();
    }

    public static void printBytes(byte[] data, String name) {
        String dataString = Base64.getEncoder().encodeToString(data);
        System.out.println(name + ": " + dataString + "\n");
    }

    public static void printBytes(byte[] data) {
        String dataString = Base64.getEncoder().encodeToString(data);
        System.out.println(dataString + "\n");
    }

    public static PublicKey recoverPubKeyFromBytes(byte[] EncodedKey) throws Exception {
        PublicKey key = KeyFactory.getInstance(keyGenAlgo).generatePublic(new X509EncodedKeySpec(EncodedKey));
        return key;
    }

}
