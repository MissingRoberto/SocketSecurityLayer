package de.uni_stuttgart.ipvs.ids.communicationLib;

import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import de.uni_stuttgart.ipvs.ids.communicationLib.crypto.InvalidSignatureException;
import de.uni_stuttgart.ipvs.ids.communicationLib.crypto.PaddingException;
import de.uni_stuttgart.ipvs.ids.communicationLib.crypto.XorCryptoProvider;

public class SLSDatagramSocket {

	DatagramSocket wrappedSocket;
	private XorCryptoProvider cryptoProvider;

	byte[] separator = { 1, 2, 3, 4 };

	public SLSDatagramSocket(DatagramSocket wrappedSocket,
			XorCryptoProvider cryptoProvider) {
		this.wrappedSocket = wrappedSocket;
		this.cryptoProvider = cryptoProvider;
	}

	/**
	 * Passes the contents of the given DatagramPacket to the cryptoPRovider for
	 * decryption. The contents of the Packet are replaced with the decrypted
	 * data.
	 * 
	 * Node: This method MUST throw an InvalidSignatureException, if the
	 * signature does not match the payload data!
	 * 
	 * @param p
	 *            The DatagramPacket whose data is to be decrypted.
	 * @throws IOException
	 *             If an error during decryption occurs.
	 */

	private int getDataLength(byte[] data, byte[] separator) throws IOException {

		for (int i = 0; i < data.length - separator.length; i++) {

			boolean found = true;
			for (int j = 0; j < separator.length; j++)
				found = found && (data[i + j] == separator[j]);

			if (found)
				return i;

		}
		throw new IOException("Separator not found");

	}

	protected void decryptPacket(DatagramPacket p) throws IOException {
		// TODO: Implement me!
		byte[] data = p.getData();
		
		int sign_length = cryptoProvider.getSignatureLength(data, p.getOffset(),
				p.getLength());


		int content_length =getDataLength(data, separator);

		byte[] content = Arrays.copyOfRange(data, 0, content_length);
		int sign_offset = content_length + separator.length;
	
		
		byte[] signature = Arrays.copyOfRange(data, sign_offset, sign_offset+sign_length );

	
		try {
			if (!cryptoProvider.checkSignature(content, signature))
				throw new InvalidSignatureException();

			p.setData(cryptoProvider.decrypt(content));
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (PaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}

	/**
	 * Passes the contents of the given DatagramPacket to the cryptoPRovider for
	 * encryption. The contents of the Packet are replaced with the encryption
	 * data.
	 * 
	 * @param p
	 *            The DatagramPacket whose data is to be encryption.
	 * @throws IOException
	 *             If an error during encryption occurs.
	 */
	protected void encryptPacket(DatagramPacket p) throws IOException {
		byte[] cypherText;
		byte[] signature;

		
		try {
			cypherText = cryptoProvider.encrypt(p.getData());
			signature = cryptoProvider.generateSignature(cypherText);

			byte[] new_mess = join(cypherText,separator);
			p.setData(join(new_mess,signature));
			

			
		} catch (PaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

	}

	public synchronized void receive(DatagramPacket p) throws IOException {
		wrappedSocket.receive(p);
		decryptPacket(p);
	}

	public void send(DatagramPacket p) throws IOException {
		encryptPacket(p);
		wrappedSocket.send(p);
	}

	public void sendWithBrokenMessage(DatagramPacket p) throws IOException {
		encryptPacket(p);
		// manipulate the message
		int signatureLength = cryptoProvider.getSignatureLength(p.getData(),
				p.getOffset(), p.getLength());
		int byteToFlip = (int) Math.rint(Math.random()
				* (p.getLength() - signatureLength));
		p.getData()[byteToFlip] ^= 1;
		wrappedSocket.send(p);
	}

	public void sendWithBrokenSignature(DatagramPacket p) throws IOException {
		encryptPacket(p);
		// manipulate the signature
		int signatureLength = cryptoProvider.getSignatureLength(p.getData(),
				p.getOffset(), p.getLength());
		int byteToFlip = (int) Math.rint(Math.random() * (signatureLength));
		byteToFlip += p.getLength() - signatureLength;
		p.getData()[byteToFlip] ^= 1;
		wrappedSocket.send(p);
	}

	public void printBytes(byte[] data) {

		for (byte b : data) {
			System.out.print(b + " ");
		}
		System.out.println("");
	}

	public byte[] join(byte[] a, byte[] b) {
		int length = a.length + b.length;
		byte[] result = new byte[length];
		System.arraycopy(a, 0, result, 0, a.length);
		System.arraycopy(b, 0, result, a.length, b.length);
		return result;
	}

}
