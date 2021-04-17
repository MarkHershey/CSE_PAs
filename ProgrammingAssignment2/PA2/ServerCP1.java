import java.io.BufferedOutputStream;
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
import java.security.SecureRandom;
import java.util.Base64;

public class ServerCP1 {
	private final static int nonceSize = 64;
	private final static Path serverCertPath = Paths.get("server_res/server_cert.crt");

	public static byte[] signBytes(byte[] targetBytes) {
		// TODO
		byte[] signedBytes = targetBytes;

		return signedBytes;
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

	public static void sendFile(DataOutputStream dest, String filename) {

	}

	public static void main(String[] args) {

		int port = 4321;
		if (args.length > 0)
			port = Integer.parseInt(args[0]);

		ServerSocket welcomeSocket = null;
		Socket connectionSocket = null;
		DataOutputStream toClient = null;
		DataInputStream fromClient = null;

		FileOutputStream fileOutputStream = null;
		BufferedOutputStream bufferedFileOutputStream = null;

		try {
			welcomeSocket = new ServerSocket(port);
			connectionSocket = welcomeSocket.accept();
			fromClient = new DataInputStream(connectionSocket.getInputStream());
			toClient = new DataOutputStream(connectionSocket.getOutputStream());

			while (!connectionSocket.isClosed()) {
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
						byte[] nonce = new byte[nonceSize];
						random.nextBytes(nonce);
						String nonceString = Base64.getEncoder().encodeToString(nonce);
						System.out.println("Generated nonce: " + nonceString);
						// sign nonce
						byte[] signedNonce = signBytes(nonce);
						// send signed nonce
						System.out.println("Sending signed nonce...");
						sendBytes(toClient, 3, signedNonce);

					}
				}

				fromClient.close();
				toClient.close();
				connectionSocket.close();

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
