import java.io.BufferedInputStream;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.Socket;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Base64;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.security.auth.x500.X500Principal;

public class ClientCP1 {
	private static int rsaKeyLength = 1024;
	private static int rsaBatchLimit = rsaKeyLength / 8 - 11;;
	private static final String cipherAsymmetricAlgo = "RSA/ECB/PKCS1Padding";
	private static final String cipherSymmetricAlgo = "AES/ECB/PKCS5Padding";
	private static PublicKey caPublicKey;
	private static PublicKey serverPublicKey;
	private static PublicKey myPublicKey;
	private static PrivateKey myPrivateKey;
	private static Key sessionKey;
	private static Cipher myEncryptCipher;
	private static Cipher serverDecryptCipher;
	private static Cipher serverEncryptCipher;
	private static MessageDigest md;

	private static void initMyKeys() throws Exception {

		// get CA's certificate
		InputStream caCertIn = new FileInputStream("ca_cert/cse_ca_cert.crt");
		CertificateFactory caCf = CertificateFactory.getInstance("X.509");
		X509Certificate caCert = (X509Certificate) caCf.generateCertificate(caCertIn);
		// init CA's public key
		caPublicKey = caCert.getPublicKey();

		// init my asymmetric keys
		KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
		keyGen.initialize(rsaKeyLength);
		KeyPair keyPair = keyGen.generateKeyPair();
		// get my key pairs
		myPublicKey = keyPair.getPublic();
		myPrivateKey = keyPair.getPrivate();
		// init my cipher
		myEncryptCipher = Cipher.getInstance(cipherAsymmetricAlgo);
		myEncryptCipher.init(Cipher.ENCRYPT_MODE, myPrivateKey);

		// init my message digest
		ClientCP1.md = MessageDigest.getInstance("MD5");

	}

	private static byte[] computeDigestForBytes(byte[] data) {
		ClientCP1.md.update(data);
		return md.digest();
	}

	private static byte[] signBytesWithMyPrivateKey(byte[] data) throws Exception {
		byte[][] batchedData = splitBytes(data);
		for (int i = 0; i < batchedData.length; i++) {
			batchedData[i] = ClientCP1.myEncryptCipher.doFinal(batchedData[i]);
		}
		return concatBytes(batchedData);
	}

	private static byte[] signBytesWithServerPubKey(byte[] data) throws Exception {
		byte[][] batchedData = splitBytes(data);
		for (int i = 0; i < batchedData.length; i++) {
			batchedData[i] = ClientCP1.serverEncryptCipher.doFinal(batchedData[i]);
		}
		return concatBytes(batchedData);
	}

	private static byte[] concatBytes(byte[][] data) throws IOException {
		ByteArrayOutputStream byteStream = new ByteArrayOutputStream();
		for (byte[] batch : data) {
			byteStream.write(batch);
		}
		return byteStream.toByteArray();
	}

	private static byte[][] splitBytes(final byte[] data) {
		// Curtsey of https://stackoverflow.com/a/32179121
		final int chunkSize = rsaBatchLimit;
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

	private static void sendBytes(DataOutputStream dest, int type, byte[] data) {
		// try {
		// dest.writeInt(type);
		// dest.writeInt(data.length);
		// byte[][] batchedData = splitBytes(data);
		// for (byte[] batch : batchedData) {
		// dest.write(batch);
		// }
		// } catch (IOException e) {
		// e.printStackTrace();
		// }
		try {
			dest.writeInt(type);
			dest.writeInt(data.length);
			dest.write(data);
		} catch (IOException e) {
			e.printStackTrace();
		}
	}

	private static byte[] receiveBytes(DataInputStream src, int expectedType) throws IOException {
		int packetType = src.readInt();

		if (packetType == expectedType) {
			int numBytes = src.readInt();
			byte[] data = new byte[numBytes];
			src.readFully(data);
			return data;
		} else {
			System.err.println("Expecting type " + expectedType + " packet but received type " + packetType);
			throw new IOException("Unexpected packet type " + expectedType);
		}
	}

	private static void sendPlainTextMessage(DataOutputStream dest, String message) {
		sendBytes(dest, 0, message.getBytes());
	}

	private static void getPublicKeyFromCertByte(byte[] certBytes) throws Exception {
		System.out.println("Checking certificate...");
		// get Server's certificate
		InputStream certIn = new ByteArrayInputStream(certBytes);
		CertificateFactory serverCf = CertificateFactory.getInstance("X.509");
		X509Certificate serverCert = (X509Certificate) serverCf.generateCertificate(certIn);

		// validate server's certificate
		serverCert.checkValidity(); // Throws a CertificateExpiredException or CertificateNotYetValidException
		serverCert.verify(caPublicKey);
		System.out.println("Server certificate is indeed signed by a known CA.");

		// System.out.println("Checking owner of certificate...");
		// X500Principal CAPrincipal = serverCert.getSubjectX500Principal();
		// String name = CAPrincipal.getName();
		// System.out.println("Signer name: " + name);

		// init Server's public key
		serverPublicKey = serverCert.getPublicKey();
		// init Decrypt Cipher using Server's public key
		serverDecryptCipher = Cipher.getInstance(cipherAsymmetricAlgo);
		serverDecryptCipher.init(Cipher.DECRYPT_MODE, serverPublicKey);
		// init Encrypt Cipher using Server's public key
		serverEncryptCipher = Cipher.getInstance(cipherAsymmetricAlgo);
		serverEncryptCipher.init(Cipher.ENCRYPT_MODE, serverPublicKey);
	}

	public static void main(String[] args) {

		String filename = "100.txt";
		if (args.length > 0)
			filename = args[0];

		String serverAddress = "localhost";
		if (args.length > 1)
			filename = args[1];

		int port = 4321;
		if (args.length > 2)
			port = Integer.parseInt(args[2]);

		int numBytes = 0;

		Socket clientSocket = null;

		DataOutputStream toServer = null;
		DataInputStream fromServer = null;

		FileInputStream fileInputStream = null;
		BufferedInputStream bufferedFileInputStream = null;

		// init keys
		try {
			initMyKeys();
		} catch (Exception e) {
			e.printStackTrace();
		}

		long timeStarted = System.nanoTime();

		try {

			System.out.println("Establishing connection to server...");

			// Connect to server and get the input and output streams
			clientSocket = new Socket(serverAddress, port);
			toServer = new DataOutputStream(clientSocket.getOutputStream());
			fromServer = new DataInputStream(clientSocket.getInputStream());

			// 1. Say Hi to server
			System.out.println("Saying Hi to server...");
			sendPlainTextMessage(toServer, "Hi");

			// 2. Get server's CA certificate
			System.out.println("Receiving server's certificate...");
			byte[] certBytes = receiveBytes(fromServer, 5);

			System.out.println("Getting server's public key from certificate...");
			getPublicKeyFromCertByte(certBytes);

			// 3. Get server's nonce
			System.out.println("Receiving server-genereated nonce...");
			byte[] nonceBytes = receiveBytes(fromServer, 3);
			String nonceString = Base64.getEncoder().encodeToString(nonceBytes);
			System.out.println("Decoded nonce: " + nonceString);

			// 4.1 Sign and send nonce back
			byte[] signedNonce = signBytesWithMyPrivateKey(nonceBytes);
			signedNonce = signBytesWithServerPubKey(signedNonce);
			System.out.println("signedNonce Length: " + signedNonce.length);
			sendBytes(toServer, 3, signedNonce);

			// 4.2 send my public key to server
			byte[] encryptedPubKey = signBytesWithServerPubKey(myPublicKey.getEncoded());
			sendBytes(toServer, 6, encryptedPubKey);

			// 5. Get server's OK

			// 6. Tell server to start session

			// 7. While-loop: Ask user input for file name or close session

			// 8. Send file

			// loop back

			// 9. Tell server to close the session

			// 10. Confirm session closed.

			clientSocket.close();

			//////////////////////////////////////////////////////

			// System.out.println("Sending file...");

			// // Send the filename
			// toServer.writeInt(0);
			// toServer.writeInt(filename.getBytes().length);
			// toServer.write(filename.getBytes());
			// // toServer.flush();

			// // Open the file
			// fileInputStream = new FileInputStream(filename);
			// bufferedFileInputStream = new BufferedInputStream(fileInputStream);

			// byte[] fromFileBuffer = new byte[117];

			// // Send the file
			// for (boolean fileEnded = false; !fileEnded;) {
			// numBytes = bufferedFileInputStream.read(fromFileBuffer);
			// fileEnded = numBytes < 117;

			// toServer.writeInt(1);
			// toServer.writeInt(numBytes);
			// toServer.write(fromFileBuffer);
			// toServer.flush();
			// }

			// bufferedFileInputStream.close();
			// fileInputStream.close();

			System.out.println("Closing connection...");

		} catch (Exception e) {
			e.printStackTrace();
		}

		long timeTaken = System.nanoTime() - timeStarted;
		System.out.println("Program took: " + timeTaken / 1000000.0 + "ms to run");
	}
}
