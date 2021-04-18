import java.io.BufferedOutputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;

import javax.crypto.Cipher;

public class ServerCP1 {
	private static byte[] nonce;
	private static final Path serverCertPath = Paths.get("server_res/server_cert.crt");
	private static final Path publicKeyPath = Paths.get("server_res/public_key.der");
	private static final Path privateKeyPath = Paths.get("server_res/private_key.der");

	private static PublicKey clientPublicKey;
	private static PublicKey myPublicKey;
	private static PrivateKey myPrivateKey;
	private static Cipher myEncryptCipher;
	private static Cipher myPubDecryptCipher;
	private static Cipher myPriDecryptCipher;
	private static Cipher clientDecryptCipher;

	private static ServerSocket welcomeSocket;
	private static Socket connectionSocket;
	private static DataOutputStream toClient;
	private static DataInputStream fromClient;

	private static void initSocket(int port) throws Exception {
		System.out.println("Set up Server Socket...");
		welcomeSocket = new ServerSocket(port);
		connectionSocket = welcomeSocket.accept();
		toClient = new DataOutputStream(connectionSocket.getOutputStream());
		fromClient = new DataInputStream(connectionSocket.getInputStream());
		System.out.println("Serve Socket initialized!");
	}

	private static void initSocket() throws Exception {
		initSocket(4321);
	}

	private static void tearDownSocket() throws IOException {
		System.out.println("Closing Serve Socket...");
		if (toClient != null)
			toClient.close();
		if (fromClient != null)
			fromClient.close();
		if (connectionSocket != null && !connectionSocket.isClosed())
			connectionSocket.close();
		if (welcomeSocket != null && !welcomeSocket.isClosed())
			welcomeSocket.close();
		System.out.println("Serve Socket closed!");
	}

	private static PrivateKey getPrivateKey(Path filepath) throws Exception {

		byte[] keyBytes = Files.readAllBytes(filepath);

		PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
		KeyFactory kf = KeyFactory.getInstance("RSA");
		return kf.generatePrivate(spec);
	}

	private static PublicKey getPublicKey(Path filepath) throws Exception {

		byte[] keyBytes = Files.readAllBytes(filepath);

		X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
		KeyFactory kf = KeyFactory.getInstance("RSA");
		return kf.generatePublic(spec);
	}

	private static void initMyKeys() throws Exception {
		// init my key pairs
		myPublicKey = getPublicKey(publicKeyPath);
		myPrivateKey = getPrivateKey(privateKeyPath);
		// init my ENCRYPT cipher
		myEncryptCipher = Cipher.getInstance(Proto.cipherAsymmetricAlgo);
		myEncryptCipher.init(Cipher.ENCRYPT_MODE, myPrivateKey);
		// init my DECRYPT cipher using public key
		myPubDecryptCipher = Cipher.getInstance(Proto.cipherAsymmetricAlgo);
		myPubDecryptCipher.init(Cipher.DECRYPT_MODE, myPublicKey);
		// init my DECRYPT cipher using private key
		myPriDecryptCipher = Cipher.getInstance(Proto.cipherAsymmetricAlgo);
		myPriDecryptCipher.init(Cipher.DECRYPT_MODE, myPrivateKey);
	}

	private static byte[] signBytesWithMyPrivateKey(byte[] data) throws Exception {
		byte[][] batchedData = Proto.splitBytesForEncryption(data);
		for (int i = 0; i < batchedData.length; i++) {
			batchedData[i] = ServerCP1.myEncryptCipher.doFinal(batchedData[i]);
		}
		return Proto.concatBytes(batchedData);
	}

	private static byte[] decryptBytesWithMyPrivateKey(byte[] data) throws Exception {
		byte[][] batchedData = Proto.splitBytesForDecryption(data);
		for (int i = 0; i < batchedData.length; i++) {
			batchedData[i] = ServerCP1.myPriDecryptCipher.doFinal(batchedData[i]);
		}
		return Proto.concatBytes(batchedData);
	}

	private static byte[] decryptBytesWithMyPubKey(byte[] data) throws Exception {
		byte[][] batchedData = Proto.splitBytesForDecryption(data);
		for (int i = 0; i < batchedData.length; i++) {
			batchedData[i] = ServerCP1.myPubDecryptCipher.doFinal(batchedData[i]);
		}
		return Proto.concatBytes(batchedData);
	}

	// private static void testEncryptDecrypt() {

	// SecureRandom random = new SecureRandom();
	// byte[] tmpRandomBytes = new byte[50];
	// random.nextBytes(tmpRandomBytes);
	// try {
	// byte[] encrypted = signBytesWithMyPrivateKey(tmpRandomBytes);
	// encrypted = signBytesWithMyPrivateKey(encrypted);
	// byte[] decrypted = decryptBytesWithMyPubKey(encrypted);
	// decrypted = decryptBytesWithMyPubKey(decrypted);
	// // printBytes(tmpRandomBytes, "before");
	// // printBytes(decrypted, "after");
	// if (Arrays.equals(tmpRandomBytes, decrypted)) {
	// System.out.println("OKKKKK");
	// } else {
	// System.out.println("NOT OK");
	// }
	// } catch (Exception e) {
	// }
	// throw new RuntimeException("fsf");
	// }

	private static byte[] decryptBytesWithClientPubKey(byte[] data) throws Exception {
		byte[][] batchedData = Proto.splitBytesForDecryption(data);
		for (int i = 0; i < batchedData.length; i++) {
			batchedData[i] = ServerCP1.clientDecryptCipher.doFinal(batchedData[i]);
		}
		return Proto.concatBytes(batchedData);
	}

	public static void sendBytes(DataOutputStream dest, int type, byte[] data) {
		try {
			dest.writeInt(type);
			dest.writeInt(data.length);
			dest.write(data);
		} catch (IOException e) {
			e.printStackTrace();
		}
	}

	public static void sendPlainTextMessage(DataOutputStream dest, String message) {
		sendBytes(dest, 0, message.getBytes());
	}

	private static void sendSignedTextMessage(DataOutputStream dest, String message) {
		try {
			System.out.println("Sending signed text message: " + message);
			byte[] signedMsg = signBytesWithMyPrivateKey(message.getBytes());
			Proto.printBytes(signedMsg, "signedMsg");
			sendBytes(dest, 7, signedMsg);
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	public static void sendFile(DataOutputStream dest, String filename) {

	}

	public static void main(String[] args) {

		try {
			initSocket();
			initMyKeys();

			while (!connectionSocket.isClosed()) {
				if (Thread.currentThread().isInterrupted()) {
					tearDownSocket();
					break;
				}
				int packetType = fromClient.readInt();

				if (packetType == 0) {
					// Receiving a message
					int numBytes = fromClient.readInt();
					byte[] messageBuffer = new byte[numBytes];
					fromClient.readFully(messageBuffer, 0, numBytes);
					String msgReceived = new String(messageBuffer, StandardCharsets.UTF_8);
					System.out.println("Received message: " + msgReceived);

					if (msgReceived.equals("Hi")) {

						// send server's certificate
						byte[] server_cert = Files.readAllBytes(serverCertPath);
						System.out.println("Sending certificate...");
						sendBytes(toClient, 5, server_cert);

						// Generate nonce
						SecureRandom random = new SecureRandom();
						ServerCP1.nonce = new byte[Proto.nonceLength];
						random.nextBytes(ServerCP1.nonce);
						Proto.printBytes(ServerCP1.nonce, "Generated nonce");
						// sign nonce
						byte[] signedNonce = signBytesWithMyPrivateKey(ServerCP1.nonce);
						// send signed nonce
						System.out.println("Sending signed nonce...");
						sendBytes(toClient, 3, signedNonce);

					}
				} else if (packetType == 6) {
					System.out.println("Receiving public key from client...");
					// Receiving a public key
					int numBytes = fromClient.readInt();
					byte[] buffer = new byte[numBytes];
					fromClient.readFully(buffer, 0, numBytes);
					byte[] decryptedBytes = decryptBytesWithMyPrivateKey(buffer);
					// init client public key
					clientPublicKey = Proto.recoverPubKeyFromBytes(decryptedBytes);
					Proto.printBytes(decryptedBytes, "clientPublicKey");
					// init client DECRYPT cipher using client's public key
					clientDecryptCipher = Cipher.getInstance(Proto.cipherAsymmetricAlgo);
					clientDecryptCipher.init(Cipher.DECRYPT_MODE, clientPublicKey);
					System.out.println("Client's public key has been initialized.");

				} else if (packetType == 3) {
					System.out.println("Verifying nonce...");
					int numBytes = fromClient.readInt();
					byte[] buffer = new byte[numBytes];
					fromClient.readFully(buffer, 0, numBytes);
					byte[] decryptedBytes = decryptBytesWithMyPrivateKey(buffer);
					byte[] decryptedNonce = decryptBytesWithClientPubKey(decryptedBytes);
					if (Arrays.equals(decryptedNonce, nonce)) {
						System.out.println("Nonce verified!");
						sendSignedTextMessage(toClient, "OK");
					} else {
						// nonce does not match
						Proto.printBytes(decryptedNonce, "DEBUG: Illegal nonce");
						Proto.printBytes(nonce, "DEBUG: Actual nonce");
						// terminate communication
						sendSignedTextMessage(toClient, "Failed");
						System.err.println("Terminating session due to nonce mismatch...");
						tearDownSocket();
					}

				} else if (packetType == 7) {
					// Receiving a message
					System.out.println("Receiving a signed message from client...");
					int numBytes = fromClient.readInt();
					byte[] messageBuffer = new byte[numBytes];
					fromClient.readFully(messageBuffer, 0, numBytes);
					// decrypt message
					byte[] decryptedMsg = decryptBytesWithClientPubKey(messageBuffer);
					String msgReceived = new String(decryptedMsg, StandardCharsets.UTF_8);

					if (msgReceived.equals("Start Session")) {
						System.out.println("Received a request from client to start a session...");
						sendSignedTextMessage(toClient, "Session Started");
						System.out.println("Session Started...");
					} else if (msgReceived.equals("Close Session")) {
						System.out.println("Received a request from client to close the session...");
						tearDownSocket();
					} else {
						System.out.println(msgReceived);
					}

				}

			}

			// while (!connectionSocket.isClosed()) {

			// int packetType = fromClient.readInt();

			// // If the packet is for transferring the filename
			// if (packetType == 0) {

			// System.out.println("Receiving file...");

			// int numBytes = fromClient.readInt();
			// byte[] filename = new byte[numBytes];
			// // Must use read fully!
			// // See:
			// //
			// https://stackoverflow.com/questions/25897627/datainputstream-read-vs-datainputstream-readfully
			// fromClient.readFully(filename, 0, numBytes);

			// fileOutputStream = new FileOutputStream("recv_" + new String(filename, 0,
			// numBytes));
			// bufferedFileOutputStream = new BufferedOutputStream(fileOutputStream);

			// // If the packet is for transferring a chunk of the file
			// } else if (packetType == 1) {

			// int numBytes = fromClient.readInt();
			// byte[] block = new byte[numBytes];
			// fromClient.readFully(block, 0, numBytes);

			// if (numBytes > 0)
			// bufferedFileOutputStream.write(block, 0, numBytes);

			// if (numBytes < 117) {
			// System.out.println("Closing connection...");

			// if (bufferedFileOutputStream != null)
			// bufferedFileOutputStream.close();
			// if (bufferedFileOutputStream != null)
			// fileOutputStream.close();
			// fromClient.close();
			// toClient.close();
			// connectionSocket.close();
			// }
			// }

			// }

		} catch (Exception e) {
			e.printStackTrace();
		}

	}

}
