import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.Key;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.logging.*;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

public class ServerCP2 {
	private static final Path serverCertPath = Paths.get("server_res/server_cert.crt");
	private static final Path publicKeyPath = Paths.get("server_res/public_key.der");
	private static final Path privateKeyPath = Paths.get("server_res/private_key.der");
	private static final String serverStoragePathStr = "server_storage";
	private static final Logger LOGGER = Logger.getLogger(ServerCP2.class.getName());

	private static PublicKey clientPublicKey;
	private static PublicKey myPublicKey;
	private static PrivateKey myPrivateKey;
	private static SecretKey sessionKey;

	private static Cipher myPriEncryptCipher;
	private static Cipher myPriDecryptCipher;
	private static Cipher clientEncryptCipher;
	private static Cipher clientDecryptCipher;
	private static Cipher sessionEncryptCipher;
	private static Cipher sessionDecryptCipher;

	private static MessageDigest md;
	private static ServerSocket welcomeSocket;
	private static Socket connectionSocket;
	private static DataOutputStream toClient;
	private static DataInputStream fromClient;

	private static int serverPort = 4321;
	private static byte[] nonce;

	///////////////////////////////////////////////////////////////////////////
	// setup & tear down methods

	private static void initLogger(Level level) {
		// Ref: https://stackoverflow.com/a/34229629
		// System.setProperty("java.util.logging.SimpleFormatter.format", "%1$tF %1$tT
		// %4$s %2$s %5$s%6$s%n");
		System.setProperty("java.util.logging.SimpleFormatter.format", "%1$tF %1$tT %4$s %5$s%6$s%n");
		Handler handlerObj = new ConsoleHandler();
		handlerObj.setLevel(level);
		LOGGER.addHandler(handlerObj);
		LOGGER.setLevel(level);
		LOGGER.setUseParentHandlers(false);
	}

	private static void initSocket() throws Exception {
		initSocket(serverPort);
	}

	private static void initSocket(int port) throws Exception {
		LOGGER.info("Set up Server Socket...");
		welcomeSocket = new ServerSocket(port);
		connectionSocket = welcomeSocket.accept();
		toClient = new DataOutputStream(connectionSocket.getOutputStream());
		fromClient = new DataInputStream(connectionSocket.getInputStream());
		LOGGER.info("OK. Server Socket is initialized.");
	}

	private static void tearDownSocket() throws IOException {
		LOGGER.info("Closing Server Socket...");
		if (toClient != null)
			toClient.close();
		if (fromClient != null)
			fromClient.close();
		if (connectionSocket != null && !connectionSocket.isClosed())
			connectionSocket.close();
		if (welcomeSocket != null && !welcomeSocket.isClosed())
			welcomeSocket.close();
		LOGGER.info("OK. Server Socket is closed.");
	}

	private static PrivateKey getPrivateKey(Path filepath) throws Exception {

		byte[] keyBytes = Files.readAllBytes(filepath);

		PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
		KeyFactory kf = KeyFactory.getInstance(Proto.keyGenAlgo);
		return kf.generatePrivate(spec);
	}

	private static PublicKey getPublicKey(Path filepath) throws Exception {

		byte[] keyBytes = Files.readAllBytes(filepath);

		X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
		KeyFactory kf = KeyFactory.getInstance(Proto.keyGenAlgo);
		return kf.generatePublic(spec);
	}

	private static void initMyKeys() throws Exception {
		// init my key pairs
		myPublicKey = getPublicKey(publicKeyPath);
		myPrivateKey = getPrivateKey(privateKeyPath);
		// init my ENCRYPT cipher using my private key
		myPriEncryptCipher = Cipher.getInstance(Proto.cipherAsymmetricAlgo);
		myPriEncryptCipher.init(Cipher.ENCRYPT_MODE, myPrivateKey);
		// init my DECRYPT cipher using my private key
		myPriDecryptCipher = Cipher.getInstance(Proto.cipherAsymmetricAlgo);
		myPriDecryptCipher.init(Cipher.DECRYPT_MODE, myPrivateKey);

		// init my message digest hash function
		md = MessageDigest.getInstance(Proto.digestAlgo);
	}

	private static void initSessionKey() throws Exception {
		LOGGER.fine("Generating session key...");
		KeyGenerator keyGen = KeyGenerator.getInstance(Proto.sessionKeyGenAlgo);
		keyGen.init(Proto.sessionKeySize);
		sessionKey = keyGen.generateKey();
		LOGGER.fine("OK. Session key is generated.");

		sessionEncryptCipher = Cipher.getInstance(Proto.cipherSymmetricAlgo);
		sessionEncryptCipher.init(Cipher.ENCRYPT_MODE, sessionKey);
		sessionDecryptCipher = Cipher.getInstance(Proto.cipherSymmetricAlgo);
		sessionDecryptCipher.init(Cipher.DECRYPT_MODE, sessionKey);
		LOGGER.fine("OK. Session ciphers are initialized.");
	}

	///////////////////////////////////////////////////////////////////////////
	// digest methods

	private static byte[] computeDigest(byte[] data) throws Exception {
		md.update(data);
		byte[] digest = md.digest();
		return digest;
	}

	private static byte[] getSignedDigest(byte[] data) throws Exception {
		byte[] digest = computeDigest(data);
		digest = signBytesWithMyPrivateKey(digest);
		assert (digest.length == Proto.signedDigestLength);
		return digest;
	}

	private static byte[] getDummyDigest() throws Exception {
		return Proto.getRandomBytes(Proto.signedDigestLength);
	}

	///////////////////////////////////////////////////////////////////////////
	// encryption & decryption methods

	private static byte[] signBytesWithMyPrivateKey(byte[] data) throws Exception {
		return Proto.encryptBytesWithCipher(data, myPriEncryptCipher);
	}

	private static byte[] decryptBytesWithMyPrivateKey(byte[] data) throws Exception {
		return Proto.decryptBytesWithCipher(data, myPriDecryptCipher);
	}

	private static byte[] encryptBytesWithClientPubKey(byte[] data) throws Exception {
		return Proto.encryptBytesWithCipher(data, clientEncryptCipher);
	}

	private static byte[] decryptBytesWithClientPubKey(byte[] data) throws Exception {
		return Proto.decryptBytesWithCipher(data, clientDecryptCipher);
	}

	private static byte[] encryptBytesWithSessionKey(byte[] data) throws Exception {
		return sessionEncryptCipher.doFinal(data);
	}

	private static byte[] decryptBytesWithSessionKey(byte[] data) throws Exception {
		return sessionDecryptCipher.doFinal(data);
	}

	///////////////////////////////////////////////////////////////////////////
	// byte-level communication methods

	private static void sendBytes(int packetType, byte[] data) throws Exception {
		toClient.writeInt(packetType); // packetType: 4 bytes
		toClient.write(getDummyDigest()); // dummy digest
		toClient.writeInt(data.length); // paylaodSize: 4 bytes
		toClient.write(data); // payload
	}

	private static void sendBytesWithProtection(int packetType, byte[] data) throws Exception {
		toClient.writeInt(packetType); // packetType: 4 bytes
		toClient.write(getSignedDigest(data)); // signed digest: 128 bytes
		// encrypt data
		byte[] encrypted = encryptBytesWithClientPubKey(data);
		toClient.writeInt(encrypted.length); // paylaodSize: 4 bytes
		toClient.write(encrypted); // payload
	}

	private static void sendBytesWithSessionProtection(int packetType, byte[] data) throws Exception {
		toClient.writeInt(packetType); // packetType: 4 bytes
		toClient.write(computeDigest(data)); // digest: 32 bytes
		// encrypt data
		byte[] encrypted = encryptBytesWithSessionKey(data);
		toClient.writeInt(encrypted.length); // paylaodSize: 4 bytes
		toClient.write(encrypted); // payload
	}

	private static byte[] receiveBytes() throws Exception {
		// ignore incoming digest
		byte[] ignoreDigest = new byte[Proto.signedDigestLength];
		fromClient.readFully(ignoreDigest);
		// get paylaodSize as an int
		int numBytes = fromClient.readInt();
		// allocate memory for incoming payload
		byte[] data = new byte[numBytes];
		// get payload
		fromClient.readFully(data);
		return data;
	}

	private static byte[] receiveEncryptedBytes() throws Exception {
		// allocate memory for incoming digest
		byte[] digest = new byte[Proto.signedDigestLength];
		// get digest
		fromClient.readFully(digest);
		// decrypt digest
		digest = decryptBytesWithClientPubKey(digest);
		// get paylaodSize as an int
		int numBytes = fromClient.readInt();
		// allocate memory for incoming payload
		byte[] data = new byte[numBytes];
		// get payload
		fromClient.readFully(data);
		// decrypt payload
		data = decryptBytesWithMyPrivateKey(data);
		// compute digest for payload received
		byte[] computedDigest = computeDigest(data);
		// verify payload digest
		if (!Arrays.equals(computedDigest, digest)) {
			LOGGER.severe("Inconsistent Digest");
			throw new Exception("Inconsistent Digest");
		} else {
			LOGGER.fine("OK. Digest verified.");
		}
		return data;
	}

	private static byte[] receiveSessionEncryptedBytes() throws Exception {
		// allocate memory for incoming digest
		byte[] digest = new byte[Proto.digestLength];
		// get digest
		fromClient.readFully(digest);
		// get paylaodSize as an int
		int numBytes = fromClient.readInt();
		// allocate memory for incoming payload
		byte[] data = new byte[numBytes];
		// get payload
		fromClient.readFully(data);
		// decrypt payload
		data = decryptBytesWithSessionKey(data);
		// compute digest for payload received
		byte[] computedDigest = computeDigest(data);
		// verify payload digest
		if (!Arrays.equals(computedDigest, digest)) {
			System.err.println("Inconsistent Digest");
			throw new Exception("Inconsistent Digest");
		}
		return data;
	}

	///////////////////////////////////////////////////////////////////////////
	// high-level communication methods

	private static void sendPlainTextMessage(String message) throws Exception {
		sendBytes(Proto.pType.plainMsg, message.getBytes());
	}

	private static void sendEncryptedTextMessage(String message) throws Exception {
		sendBytesWithProtection(Proto.pType.encryptedMsg, message.getBytes());
	}

	private static void sendSessionEncryptedTextMessage(String message) throws Exception {
		sendBytesWithSessionProtection(Proto.pType.sEncryptedMsg, message.getBytes());
	}

	private static String receivePlainTextMessage() throws Exception {
		byte[] bytesRecieved = receiveBytes();
		String msg = new String(bytesRecieved, StandardCharsets.UTF_8);
		LOGGER.fine("Received plain message: '" + msg + "'");
		return msg;
	}

	private static String receiveEncryptedTextMessage() throws Exception {
		byte[] bytesRecieved = receiveEncryptedBytes();
		String msg = new String(bytesRecieved, StandardCharsets.UTF_8);
		LOGGER.fine("Received encrypted message: '" + msg + "'");
		return msg;
	}

	private static String receiveSessionEncryptedTextMessage() throws Exception {
		byte[] bytesRecieved = receiveSessionEncryptedBytes();
		String msg = new String(bytesRecieved, StandardCharsets.UTF_8);
		LOGGER.fine("Received encrypted message: '" + msg + "'");
		return msg;
	}

	private static void saveFile(byte[] data, String name) throws IOException {
		Path path = Paths.get(serverStoragePathStr + "/recv_" + name);
		Files.write(path, data);
		LOGGER.info("OK. File saved to: " + path.toString());
	}

	///////////////////////////////////////////////////////////////////////////

	public static void main(String[] args) {
		initLogger(Level.ALL);

		try {
			initSocket();
			initMyKeys();

			while (!connectionSocket.isClosed()) {

				if (Thread.currentThread().isInterrupted()) {
					tearDownSocket();
					break;
				}

				byte[] bytesRecieved;
				int packetType = fromClient.readInt();

				if (packetType == Proto.pType.plainMsg) {
					String msgReceived = receivePlainTextMessage();
					if (msgReceived.equals("Hi")) {
						// send server's certificate
						byte[] server_cert = Files.readAllBytes(serverCertPath);
						LOGGER.fine("Sending certificate...");
						sendBytes(Proto.pType.cert, server_cert);
						// Generate nonce
						SecureRandom random = new SecureRandom();
						nonce = new byte[Proto.nonceLength];
						random.nextBytes(nonce);
						LOGGER.fine("Generated nonce: " + Proto.bytesToString(nonce));
						// sign nonce
						byte[] signedNonce = signBytesWithMyPrivateKey(nonce);
						// send signed nonce
						LOGGER.fine("Sending signed nonce...");
						sendBytes(Proto.pType.nonce, signedNonce);

					}
				}

				else if (packetType == Proto.pType.encryptedMsg) {
					String msgReceived = receiveEncryptedTextMessage();
					if (msgReceived.equals("Start Session")) {
						LOGGER.fine("Received a request from client to start a session...");
						// generate session key and init session ciphers
						initSessionKey();
						LOGGER.fine("Session Key: " + Proto.bytesToString(sessionKey.getEncoded()));
						// send session key
						sendBytesWithProtection(Proto.pType.sessionKey, sessionKey.getEncoded());
						sendSessionEncryptedTextMessage("Session Started");
						LOGGER.fine("OK. Session Started.");
					} else if (msgReceived.equals("Close Session")) {
						LOGGER.fine("Received a request from client to close the session...");
						tearDownSocket();
						break;
					} else {
						LOGGER.warning("Received unexpected encrypted message: " + msgReceived);
					}
				}

				else if (packetType == Proto.pType.sEncryptedMsg) {
					String msgReceived = receiveSessionEncryptedTextMessage();
					if (msgReceived.equals("Close Session")) {
						LOGGER.fine("Received a request from client to close the session...");
						tearDownSocket();
						break;
					} else {
						LOGGER.warning("Received unexpected encrypted message: " + msgReceived);
					}
				}

				else if (packetType == Proto.pType.pubKey) {
					LOGGER.fine("Receiving public key from client...");
					// Receiving a public key
					bytesRecieved = receiveBytes();
					byte[] decryptedBytes = decryptBytesWithMyPrivateKey(bytesRecieved);
					// init client public key
					clientPublicKey = Proto.recoverPubKeyFromBytes(decryptedBytes);
					LOGGER.fine("clientPublicKey: " + Proto.bytesToString(decryptedBytes));
					// init client ENCRYPT cipher using client's public key
					clientEncryptCipher = Cipher.getInstance(Proto.cipherAsymmetricAlgo);
					clientEncryptCipher.init(Cipher.ENCRYPT_MODE, clientPublicKey);
					// init client DECRYPT cipher using client's public key
					clientDecryptCipher = Cipher.getInstance(Proto.cipherAsymmetricAlgo);
					clientDecryptCipher.init(Cipher.DECRYPT_MODE, clientPublicKey);
					LOGGER.info("OK. Client's public key has been initialized.");
				}

				else if (packetType == Proto.pType.nonce) {
					LOGGER.fine("Verifying nonce...");
					bytesRecieved = receiveBytes();
					byte[] decryptedBytes = decryptBytesWithMyPrivateKey(bytesRecieved);
					byte[] decryptedNonce = decryptBytesWithClientPubKey(decryptedBytes);
					if (Arrays.equals(decryptedNonce, nonce)) {
						LOGGER.info("OK. Nonce verified.");
						sendEncryptedTextMessage("Ready");
					} else {
						// nonce does not match
						LOGGER.fine("DEBUG: Illegal nonce: " + Proto.bytesToString(decryptedNonce));
						LOGGER.fine("DEBUG: Actual nonce : " + Proto.bytesToString(nonce));
						// terminate communication
						sendEncryptedTextMessage("Failed");
						LOGGER.severe("Terminating session due to nonce mismatch...");
						tearDownSocket();
						break;
					}
				}

				else if (packetType == Proto.pType.filename) {
					LOGGER.fine("Receiving a file...");
					// expecting a filename
					bytesRecieved = receiveEncryptedBytes();
					String fileName = new String(bytesRecieved, StandardCharsets.UTF_8);
					LOGGER.fine("OK. Filename: " + fileName);
					// expecting the file content
					packetType = fromClient.readInt();
					bytesRecieved = receiveEncryptedBytes();
					saveFile(bytesRecieved, fileName);
					// send confirmation
					sendEncryptedTextMessage("File Received");
				}

				else if (packetType == Proto.pType.sFilename) {
					LOGGER.fine("Receiving a file...");
					// expecting a filename
					bytesRecieved = receiveSessionEncryptedBytes();
					String fileName = new String(bytesRecieved, StandardCharsets.UTF_8);
					LOGGER.fine("OK. Filename: " + fileName);
					// expecting the file content
					packetType = fromClient.readInt();
					bytesRecieved = receiveSessionEncryptedBytes();
					saveFile(bytesRecieved, fileName);
					// send confirmation
					sendSessionEncryptedTextMessage("File Received");
				}

			}

		} catch (Exception e) {
			LOGGER.log(Level.SEVERE, e.getMessage(), e);
			e.printStackTrace();
		}

	}

}
