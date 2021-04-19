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
import java.util.Arrays;
import java.util.Scanner;
import javax.crypto.Cipher;

public class ClientCP1 {
	private static PublicKey caPublicKey;
	private static PublicKey serverPublicKey;
	private static PublicKey myPublicKey;
	private static PrivateKey myPrivateKey;
	private static Key sessionKey;

	private static Cipher myPriEncryptCipher;
	private static Cipher myPriDecryptCipher;
	private static Cipher serverEncryptCipher;
	private static Cipher serverDecryptCipher;

	private static MessageDigest md;
	private static Socket clientSocket;
	private static DataOutputStream toServer;
	private static DataInputStream fromServer;

	private static String serverAddress = "localhost";
	private static int serverPort = 4321;
	private static String filename;

	///////////////////////////////////////////////////////////////////////////
	// setup & tear down methods

	private static void initSocket(String serverAddress, int port) throws Exception {
		// Connect to server and get the input and output streams
		System.out.println("Establishing connection to server...");
		clientSocket = new Socket(serverAddress, port);
		toServer = new DataOutputStream(clientSocket.getOutputStream());
		fromServer = new DataInputStream(clientSocket.getInputStream());
		System.out.println("Client socket initialized!");
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
		InputStream caCertIn = new FileInputStream(Proto.caCertificatePath);
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
		myPriEncryptCipher = Cipher.getInstance(Proto.cipherAsymmetricAlgo);
		myPriEncryptCipher.init(Cipher.ENCRYPT_MODE, myPrivateKey);
		myPriDecryptCipher = Cipher.getInstance(Proto.cipherAsymmetricAlgo);
		myPriDecryptCipher.init(Cipher.DECRYPT_MODE, myPrivateKey);
		// init my message digest hash function
		md = MessageDigest.getInstance(Proto.digestAlgo);
	}

	private static void initServerPublicKeyFromCertByte(byte[] certBytes) throws Exception {
		System.out.println("Checking Server's certificate...");
		// get Server's certificate
		InputStream certIn = new ByteArrayInputStream(certBytes);
		CertificateFactory serverCf = CertificateFactory.getInstance("X.509");
		X509Certificate serverCert = (X509Certificate) serverCf.generateCertificate(certIn);

		// validate server's certificate
		serverCert.checkValidity(); // Throws a CertificateExpiredException or CertificateNotYetValidException
		serverCert.verify(caPublicKey);
		System.out.println("Server's certificate is indeed signed by a known CA.");

		// System.out.println("Checking the owner of certificate...");
		// X500Principal CAPrincipal = serverCert.getSubjectX500Principal();
		// String ownerName = CAPrincipal.getName();
		// System.out.println("Owner name: " + ownerName);

		// init Server's public key
		serverPublicKey = serverCert.getPublicKey();
		// init Decrypt Cipher using Server's public key
		serverDecryptCipher = Cipher.getInstance(Proto.cipherAsymmetricAlgo);
		serverDecryptCipher.init(Cipher.DECRYPT_MODE, serverPublicKey);
		// init Encrypt Cipher using Server's public key
		serverEncryptCipher = Cipher.getInstance(Proto.cipherAsymmetricAlgo);
		serverEncryptCipher.init(Cipher.ENCRYPT_MODE, serverPublicKey);
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

	private static byte[] encryptBytesWithServerPubKey(byte[] data) throws Exception {
		return Proto.encryptBytesWithCipher(data, serverEncryptCipher);
	}

	private static byte[] decryptBytesWithServerPubKey(byte[] data) throws Exception {
		return Proto.decryptBytesWithCipher(data, serverDecryptCipher);
	}

	///////////////////////////////////////////////////////////////////////////
	// byte-level communication methods

	private static void sendBytes(int packetType, byte[] data) throws Exception {
		toServer.writeInt(packetType); // packetType: 4 bytes
		toServer.write(getDummyDigest()); // dummy digest
		toServer.writeInt(data.length); // paylaodSize: 4 bytes
		toServer.write(data); // payload
	}

	private static void sendBytesWithProtection(int packetType, byte[] data) throws Exception {
		toServer.writeInt(packetType); // packetType: 4 bytes
		toServer.write(getSignedDigest(data)); // signed digest: 128 bytes
		// encrypt data
		byte[] encrypted = encryptBytesWithServerPubKey(data);
		toServer.writeInt(encrypted.length); // paylaodSize: 4 bytes
		toServer.write(encrypted); // payload
	}

	private static byte[] receiveBytes(int expectedType) throws Exception {
		// get packetType as an int
		int packetType = fromServer.readInt();

		if (packetType == expectedType) {
			// ignore incoming digest
			byte[] ignoreDigest = new byte[Proto.signedDigestLength];
			fromServer.readFully(ignoreDigest);
			// get paylaodSize as an int
			int numBytes = fromServer.readInt();
			// allocate memory for incoming payload
			byte[] data = new byte[numBytes];
			// get payload
			fromServer.readFully(data);
			return data;
		} else {
			String expectedTypeStr = Proto.pType.map.get(expectedType);
			String packetTypeStr = Proto.pType.map.get(packetType);
			System.err.println("Expecting packetType " + expectedTypeStr + " but received packetType " + packetTypeStr);
			throw new IOException("Unexpected packetType");
		}
	}

	private static byte[] receiveEncryptedBytes(int expectedType) throws Exception {
		// get packetType as an int
		int packetType = fromServer.readInt();

		if (packetType == expectedType) {
			// allocate memory for incoming digest
			byte[] digest = new byte[Proto.signedDigestLength];
			// get digest
			fromServer.readFully(digest);
			// decrypt digest
			digest = decryptBytesWithServerPubKey(digest);
			// get paylaodSize as an int
			int numBytes = fromServer.readInt();
			// allocate memory for incoming payload
			byte[] data = new byte[numBytes];
			// get payload
			fromServer.readFully(data);
			// decrypt payload
			data = decryptBytesWithMyPrivateKey(data);
			// compute digest for payload received
			byte[] computedDigest = computeDigest(data);
			// verify payload digest
			if (!Arrays.equals(computedDigest, digest)) {
				System.err.println("Inconsistent Digest");
				throw new Exception("Inconsistent Digest");
			}
			return data;
		} else {
			String expectedTypeStr = Proto.pType.map.get(expectedType);
			String packetTypeStr = Proto.pType.map.get(packetType);
			System.err.println("Expecting packetType " + expectedTypeStr + " but received packetType " + packetTypeStr);
			throw new IOException("Unexpected packetType");
		}
	}

	///////////////////////////////////////////////////////////////////////////
	// high-level communication methods

	private static void sendPlainTextMessage(String message) throws Exception {
		sendBytes(Proto.pType.plainMsg, message.getBytes());
	}

	private static void sendEncryptedTextMessage(String message) throws Exception {
		sendBytesWithProtection(Proto.pType.encryptedMsg, message.getBytes());
	}

	private static void sendFile(String filename) throws Exception {
		File file = new File(filename);
		assert file.exists();
		// send filename
		sendBytesWithProtection(Proto.pType.filename, file.getName().getBytes());
		// get file content
		FileInputStream fileInputStream = new FileInputStream(file);
		byte[] fileBytes = new byte[(int) file.length()];
		fileInputStream.read(fileBytes);
		// send file content
		sendBytesWithProtection(Proto.pType.file, fileBytes);
		fileInputStream.close();
		System.out.println("File sent: " + filename);
	}

	private static String receivePlainTextMessage() throws Exception {
		byte[] bytesRecieved = receiveBytes(Proto.pType.plainMsg);
		return new String(bytesRecieved, StandardCharsets.UTF_8);
	}

	private static String receiveEncryptedTextMessage() throws Exception {
		byte[] bytesRecieved = receiveEncryptedBytes(Proto.pType.encryptedMsg);
		return new String(bytesRecieved, StandardCharsets.UTF_8);
	}

	///////////////////////////////////////////////////////////////////////////

	public static void main(String[] args) {
		// validate filename
		if (args.length > 0) {
			File file = new File(args[0]);
			if (!file.exists()) {
				file = new File("client_res/" + args[0]);
				if (!file.exists()) {
					System.out.println("File '" + args[0] + "' not found.");
					return;
				} else {
					filename = "client_res/" + args[0];
				}
			} else {
				filename = args[0];
			}
		}

		// initialize socket connection and keys
		try {
			if (args.length > 1)
				serverAddress = args[1];
			if (args.length > 2)
				serverPort = Integer.parseInt(args[2]);
			initSocket(serverAddress, serverPort);
			initMyKeys();
		} catch (Exception e) {
			e.printStackTrace();
			return;
		}

		long timeStarted = System.nanoTime();

		try {
			byte[] bytesRecieved;

			// 1. Say Hi to server
			System.out.println("Saying Hi to server...");
			sendPlainTextMessage("Hi");

			// 2. Get server's CA certificate
			System.out.println("Receiving server's certificate...");
			bytesRecieved = receiveBytes(Proto.pType.cert);

			System.out.println("Getting server's public key from certificate...");
			initServerPublicKeyFromCertByte(bytesRecieved);

			// 3. Get server's nonce
			System.out.println("Receiving server-genereated nonce...");
			bytesRecieved = receiveBytes(Proto.pType.nonce);
			byte[] decryptedNonceBytes = decryptBytesWithServerPubKey(bytesRecieved);
			Proto.printBytes(decryptedNonceBytes, "decryptedNonce");

			// 4.1 send my public key to server
			System.out.println("Sending my public key to server...");
			Proto.printBytes(myPublicKey.getEncoded(), "myPublicKey");
			byte[] encryptedPubKey = encryptBytesWithServerPubKey(myPublicKey.getEncoded());
			sendBytes(Proto.pType.pubKey, encryptedPubKey);

			// 4.2 Sign and send nonce back
			System.out.println("Sending back signed nonce...");
			byte[] signedNonce = signBytesWithMyPrivateKey(decryptedNonceBytes);
			signedNonce = encryptBytesWithServerPubKey(signedNonce);
			Proto.printBytes(signedNonce, "DEBUG: Sending signed nonce");
			sendBytes(Proto.pType.nonce, signedNonce);

			// 5. Get server's OK
			System.out.println("Receiving server confirmation...");
			String confirmationMsg = receiveEncryptedTextMessage();
			if (confirmationMsg.equals("Ready")) {
				System.out.println("Authentication Handshake Complete.");
			} else {
				System.err.println("Authentication failed, terminating communication...");
				tearDownSocket();
				return;
			}

			// 6. Tell server to start session
			System.out.println("Tell server to start a session...");
			sendEncryptedTextMessage("Start Session");

			// 6.2 Confirm session has started
			System.out.println("Receiving session confirmation...");
			confirmationMsg = receiveEncryptedTextMessage();
			if (confirmationMsg.equals("Session Started")) {
				System.out.println("Session Started");
			} else {
				System.err.println("Session refused, terminating communication...");
				tearDownSocket();
				return;
			}

			if (filename == null) {
				// 7.1 While-loop: Ask user input for file name or close session
				Scanner myScanner = new Scanner(System.in);
				while (true) {
					System.out.println("\nEnter filename to send file (enter 'q' to quit):");
					String usrInput = myScanner.nextLine();

					if (usrInput.equals("q")) {
						break;
					}

					File file = new File(usrInput);
					if (!file.exists()) {
						file = new File("client_res/" + usrInput);
						if (!file.exists()) {
							System.out.println("File '" + usrInput + "' not found.");
							continue;
						}
					}

					// 7.2. Send file
					long fileTransferStarted = System.nanoTime();
					sendFile(file.getPath());
					// pending confirmation
					System.out.println("Pending confirmation...");
					confirmationMsg = receiveEncryptedTextMessage();
					if (confirmationMsg.equals("File Received")) {
						System.out.println("Server Received");
					} else {
						System.err.println("Error: Server failed to receive the file.");
						continue;
					}

					// calculate time
					long fileTransferTaken = System.nanoTime() - fileTransferStarted;
					System.out.println("File transfer took: " + fileTransferTaken / 1000000.0 + "ms");
				}
				myScanner.close();

			} else {
				sendFile(filename);
				// pending confirmation
				System.out.println("Pending confirmation...");
				confirmationMsg = receiveEncryptedTextMessage();
				if (confirmationMsg.equals("File Received")) {
					System.out.println("Server Received");
				} else {
					System.err.println("Error: Server failed to receive the file.");
				}
			}

			// 9. Tell server to close the session
			System.out.println("Tell server to close the session...");
			sendEncryptedTextMessage("Close Session");

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
