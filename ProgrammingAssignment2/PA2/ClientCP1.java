import java.io.BufferedInputStream;
import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.Socket;
import java.security.Key;
import java.security.PublicKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Base64;

import javax.security.auth.x500.X500Principal;

public class ClientCP1 {
	private static Key mykey = null;

	public static void sendBytes(DataOutputStream dest, int type, byte[] data) {
		try {
			dest.writeInt(type);
			dest.writeInt(data.length);
			dest.write(data);
		} catch (IOException e) {
			e.printStackTrace();
		}
	}

	public static byte[] receiveBytes(DataInputStream src, int expectedType) throws IOException {
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

	public static void sendPlainTextMessage(DataOutputStream dest, String message) {
		sendBytes(dest, 0, message.getBytes());
	}

	public static PublicKey getPublicKeyFromCertByte(byte[] certBytes) throws Exception {
		System.out.println("Checking certificate...");
		InputStream certIn = new ByteArrayInputStream(certBytes);
		CertificateFactory serverCf = CertificateFactory.getInstance("X.509");
		X509Certificate serverCert = (X509Certificate) serverCf.generateCertificate(certIn);

		// Load CA's public key
		InputStream CAFis = new FileInputStream("ca_cert/cse_ca_cert.crt");
		CertificateFactory CACf = CertificateFactory.getInstance("X.509");
		X509Certificate CAcert = (X509Certificate) CACf.generateCertificate(CAFis);

		PublicKey CAKey = CAcert.getPublicKey();

		serverCert.checkValidity(); // Throws a CertificateExpiredException or CertificateNotYetValidException if
									// invalid
		serverCert.verify(CAKey);
		System.out.println("Server certificate is signed by CA!");

		System.out.println("Checking owner of certificate...");

		X500Principal CAPrincipal = serverCert.getSubjectX500Principal();
		String name = CAPrincipal.getName();
		// System.out.println("Signer name: " + name);

		// Get Pubkey
		PublicKey serverPublicKey = serverCert.getPublicKey();
		return serverPublicKey;
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
			PublicKey serverPublicKey = getPublicKeyFromCertByte(certBytes);

			// 3. Get server's nonce
			System.out.println("Receiving server-genereated nonce...");
			byte[] nonceBytes = receiveBytes(fromServer, 3);
			String nonceString = Base64.getEncoder().encodeToString(nonceBytes);
			System.out.println("Decoded nonce: " + nonceString);

			// 4. Sign and send nonce back

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
