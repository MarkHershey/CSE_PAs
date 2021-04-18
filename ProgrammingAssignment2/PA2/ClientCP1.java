import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Scanner;
import javax.crypto.Cipher;

public class ClientCP1 {
	private static PublicKey caPublicKey;
	private static PublicKey serverPublicKey;
	private static PublicKey myPublicKey;
	private static PrivateKey myPrivateKey;
	private static Key sessionKey;
	private static Cipher myEncryptCipher;
	private static Cipher serverDecryptCipher;
	private static Cipher serverEncryptCipher;
	private static MessageDigest md;
	private static Socket clientSocket;
	private static DataOutputStream toServer;
	private static DataInputStream fromServer;

	private static void initSocket(String serverAddress, int port) throws Exception {
		// Connect to server and get the input and output streams
		System.out.println("Establishing connection to server...");
		clientSocket = new Socket(serverAddress, port);
		toServer = new DataOutputStream(clientSocket.getOutputStream());
		fromServer = new DataInputStream(clientSocket.getInputStream());
		System.out.println("Client socket initialized!");
	}

	private static void initSocket() throws Exception {
		initSocket("localhost", 4321);
	}

	private static void tearDownSocket() throws IOException {
		System.out.println("Closing connection to server...");
		if (toServer != null)
			toServer.close();
		if (fromServer != null)
			fromServer.close();
		if (clientSocket != null && !clientSocket.isClosed())
			clientSocket.close();
		System.out.println("Connection closed!");
	}

	private static void initMyKeys() throws Exception {

		// get CA's certificate
		InputStream caCertIn = new FileInputStream("ca_cert/cse_ca_cert.crt");
		CertificateFactory caCf = CertificateFactory.getInstance(Proto.certificateType);
		X509Certificate caCert = (X509Certificate) caCf.generateCertificate(caCertIn);
		// init CA's public key
		caPublicKey = caCert.getPublicKey();

		// init my asymmetric keys
		KeyPairGenerator keyGen = KeyPairGenerator.getInstance(Proto.keyGenAlgo);
		keyGen.initialize(Proto.rsaKeyLength);
		KeyPair keyPair = keyGen.generateKeyPair();
		// get my key pairs
		myPublicKey = keyPair.getPublic();
		myPrivateKey = keyPair.getPrivate();
		// init my cipher
		myEncryptCipher = Cipher.getInstance(Proto.cipherAsymmetricAlgo);
		myEncryptCipher.init(Cipher.ENCRYPT_MODE, myPrivateKey);

		// init my message digest
		ClientCP1.md = MessageDigest.getInstance(Proto.digestAlgo);

	}

	private static byte[] generateAndSignDigest(byte[] data) throws Exception {
		md.update(data);
		byte[] digest = md.digest();
		digest = signBytesWithMyPrivateKey(digest);
		return digest;
	}

	private static byte[] signBytesWithMyPrivateKey(byte[] data) throws Exception {
		byte[][] batchedData = Proto.splitBytesForEncryption(data);
		for (int i = 0; i < batchedData.length; i++) {
			batchedData[i] = ClientCP1.myEncryptCipher.doFinal(batchedData[i]);
		}
		return Proto.concatBytes(batchedData);
	}

	private static byte[] signBytesWithServerPubKey(byte[] data) throws Exception {
		byte[][] batchedData = Proto.splitBytesForEncryption(data);
		for (int i = 0; i < batchedData.length; i++) {
			batchedData[i] = ClientCP1.serverEncryptCipher.doFinal(batchedData[i]);
		}
		return Proto.concatBytes(batchedData);
	}

	private static byte[] decryptBytesWithServerPubKey(byte[] data) throws Exception {
		byte[][] batchedData = Proto.splitBytesForDecryption(data);
		for (int i = 0; i < batchedData.length; i++) {
			batchedData[i] = ClientCP1.serverDecryptCipher.doFinal(batchedData[i]);
		}
		return Proto.concatBytes(batchedData);
	}

	private static void sendBytes(DataOutputStream dest, int type, byte[] data) {
		try {
			dest.writeInt(type);
			dest.writeInt(data.length);
			dest.write(data);
		} catch (IOException e) {
			e.printStackTrace();
		}
	}

	private static void sendBytesWithDigest(DataOutputStream dest, int type, byte[] data) {
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

	private static void sendSignedTextMessage(DataOutputStream dest, String message) {
		try {
			byte[] signedMsg = signBytesWithMyPrivateKey(message.getBytes());
			sendBytes(dest, 7, signedMsg);
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	private static String receiveSignedMsgFromServer(DataInputStream src) throws Exception {
		byte[] bytesRecieved = receiveBytes(src, 7);
		byte[] decryptBytes = decryptBytesWithServerPubKey(bytesRecieved);
		String msgReceived = new String(decryptBytes, StandardCharsets.UTF_8);
		return msgReceived;
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
		serverDecryptCipher = Cipher.getInstance(Proto.cipherAsymmetricAlgo);
		serverDecryptCipher.init(Cipher.DECRYPT_MODE, serverPublicKey);
		// init Encrypt Cipher using Server's public key
		serverEncryptCipher = Cipher.getInstance(Proto.cipherAsymmetricAlgo);
		serverEncryptCipher.init(Cipher.ENCRYPT_MODE, serverPublicKey);
	}

	// public static void testEncrypt() {
	// try {
	// initMyKeys();
	// } catch (Exception e1) {
	// e1.printStackTrace();
	// }
	// SecureRandom random = new SecureRandom();
	// byte[] nonce = new byte[10];
	// random.nextBytes(nonce);
	// try {
	// byte[] tmp = signBytesWithMyPrivateKey(nonce);
	// if (tmp.length == nonce.length) {
	// System.out.println("OKOKOOK");
	// } else {
	// System.out.println("nonce: " + nonce.length);
	// System.out.println("tmp: " + tmp.length);
	// }
	// } catch (Exception e) {
	// e.printStackTrace();
	// }
	// throw new RuntimeException("fsf");
	// }

	// private static void testDigest() {
	// try {
	// initMyKeys();
	// for (int i = 0; i < 10; i++) {
	// int size = i * 1111;
	// SecureRandom random = new SecureRandom();
	// byte[] data = new byte[size];
	// random.nextBytes(data);
	// System.out.println("Data length: " + data.length);
	// data = generateAndSignDigest(data);
	// System.out.println("Digest length: " + data.length);
	// }
	// } catch (Exception e) {
	// }
	// throw new RuntimeException("fsf");
	// }

	public static void main(String[] args) {
		// initialize socket connection and keys
		try {
			initSocket();
			initMyKeys();
		} catch (Exception e) {
			e.printStackTrace();
			return;
		}

		long timeStarted = System.nanoTime();

		try {
			// temporary variables
			byte[] bytesRecieved;

			// 1. Say Hi to server
			System.out.println("Saying Hi to server...");
			sendPlainTextMessage(toServer, "Hi");

			// 2. Get server's CA certificate
			System.out.println("Receiving server's certificate...");
			bytesRecieved = receiveBytes(fromServer, 5);

			System.out.println("Getting server's public key from certificate...");
			getPublicKeyFromCertByte(bytesRecieved);

			// 3. Get server's nonce
			System.out.println("Receiving server-genereated nonce...");
			bytesRecieved = receiveBytes(fromServer, 3);
			byte[] decryptedNonceBytes = decryptBytesWithServerPubKey(bytesRecieved);
			Proto.printBytes(decryptedNonceBytes, "decryptedNonce");

			// 4.1 send my public key to server
			System.out.println("Sending client's public key to server...");
			Proto.printBytes(myPublicKey.getEncoded(), "myPublicKey");
			byte[] encryptedPubKey = signBytesWithServerPubKey(myPublicKey.getEncoded());
			sendBytes(toServer, 6, encryptedPubKey);

			// 4.2 Sign and send nonce back
			System.out.println("Sending back signed nonce...");
			byte[] signedNonce = signBytesWithMyPrivateKey(decryptedNonceBytes);
			signedNonce = signBytesWithServerPubKey(signedNonce);
			Proto.printBytes(signedNonce, "DEBUG: Sending signed nonce");
			sendBytes(toServer, 3, signedNonce);

			// 5. Get server's OK
			System.out.println("Receiving server confirmation...");
			String confirmationMsg = receiveSignedMsgFromServer(fromServer);
			if (confirmationMsg.equals("OK")) {
				System.out.println("Authentication Handshake Complete.");
			} else {
				System.err.println("Authentication failed, terminating communication...");
				System.err.println(confirmationMsg);
				toServer.close();
				fromServer.close();
				clientSocket.close();
				return;
			}

			// 6. Tell server to start session
			System.out.println("Tell server to start a session...");
			sendSignedTextMessage(toServer, "Start Session");

			// 6.2 Confirm session has started
			System.out.println("Receiving session confirmation...");
			confirmationMsg = receiveSignedMsgFromServer(fromServer);
			if (confirmationMsg.equals("Session Started")) {
				System.out.println("Session Started");
			} else {
				System.err.println("Session refused, terminating communication...");
				System.err.println(confirmationMsg);
				toServer.close();
				fromServer.close();
				clientSocket.close();
				return;
			}

			// 7. While-loop: Ask user input for file name or close session
			Scanner myScanner = new Scanner(System.in);
			while (true) {
				System.out.println("Enter filename to send file:");
				String usrInput = myScanner.nextLine();

				if (usrInput.equals("quit")) {
					break;
				}

				File file = new File(usrInput);
				if (!file.exists()) {
					file = new File("client_res/" + usrInput);
					if (!file.exists()) {
						System.out.println("File not found.");
						continue;
					}
				}
				FileInputStream fileInputStream = new FileInputStream(file);
				byte[] fileBytes = new byte[(int) file.length()];
				fileInputStream.read(fileBytes);
			}
			myScanner.close();

			// 8. Send file

			// loop back

			// 9. Tell server to close the session
			System.out.println("Tell server to close the session...");
			sendSignedTextMessage(toServer, "Close Session");

			// 10. Confirm session closed.
			tearDownSocket();

		} catch (Exception e) {
			e.printStackTrace();
		}
		// calculate throughput time cost
		long timeTaken = System.nanoTime() - timeStarted;
		System.out.println("Program took: " + timeTaken / 1000000.0 + "ms to run");
	}
}
