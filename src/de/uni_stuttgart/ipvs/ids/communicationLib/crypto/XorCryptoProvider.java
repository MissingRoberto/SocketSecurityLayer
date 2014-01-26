package de.uni_stuttgart.ipvs.ids.communicationLib.crypto;

import java.io.UnsupportedEncodingException;
import java.nio.charset.Charset;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.util.BitSet;

public class XorCryptoProvider {

	/**
	 * The shared secret key used for encryption/decryption.
	 */
	protected byte[] key = null;

	/**
	 * Converts the given String (in UTF-8 interpretation) to a byte array which
	 * is in turn used as the key.
	 * 
	 * @param key
	 *            The key to be used for encryption/decryption/signing
	 * @throws KeyTooLongException
	 *             If the key is longer than this implementation can handle
	 */
	public void setKey(String key) throws KeyTooLongException {
		this.setKey(key.getBytes(Charset.forName("UTF8")));
	}

	/**
	 * Sets the given byte array as the key for this XorCryptoProvider.
	 * 
	 * @param key
	 *            The key to be used for encryption/decryption/signing
	 * @throws KeyTooLongException
	 *             If the key is longer than this implementation can handle
	 */
	public void setKey(byte[] key) throws KeyTooLongException {
		if (key.length > Byte.MAX_VALUE) {
			throw new KeyTooLongException(key.length, Byte.MAX_VALUE);
		}
		this.key = key;
	}

	/**
	 * Create a new array with the data from the original plain array plus
	 * padding at the end.
	 * 
	 * @param plain
	 *            The data to be padded.
	 * @return A new array containing the padded data.
	 * @throws PaddingException
	 *             If an error occurs during creating the padding data.
	 */
	protected byte[] addPadding(byte[] plain) throws PaddingException {
		// TODO: Implement me!
		int block_size = key.length;
		byte[] padded = new byte[plain.length - plain.length % block_size
				+ block_size];
		int padding = block_size - plain.length % block_size;

		System.arraycopy(plain, 0, padded, 0, plain.length);
		fillArray(padded, plain.length, padding);

		return padded;

	}

	/**
	 * Creates a new array with only payload data, without the padding data.
	 * Verifies that the padding data is intact.
	 * 
	 * @param data
	 *            The padded data
	 * @return A new array containing only payload data.
	 * @throws PaddingException
	 *             Thrown if either the input is of incorrect length or if the
	 *             padding data is not intact.
	 */
	protected byte[] removePadding(byte[] data) throws PaddingException {
		// TODO: Implement me!

	
		int padding = (int) data[data.length - 1];
		int new_size = data.length - padding;
		
		printBytes(data);
		
		
		
		for (int i = new_size; i < data.length; i++) {
			
			if (data[i] != padding)
				throw new PaddingException();
		}
		
	

		byte[] plain = new byte[new_size];
		System.arraycopy(data, 0, plain, 0, new_size);
		
		return plain;
	}

	/**
	 * Encrypts the given byte array. The encrypted data is stored in a new
	 * array that is returned. The new array may be longer than the input, since
	 * padding may have been added.
	 * 
	 * @param plain
	 *            The plaintext data
	 * @param offset
	 *            Offset for the start of the data in the input
	 * @param length
	 *            Length of data in the input
	 * @return A new array containing the encrypted data, padded to match the
	 *         block size.
	 * @throws PaddingException
	 *             Thrown if an error occurs during padding the data.
	 */
	public byte[] encrypt(byte[] plain) throws PaddingException {
		// TODO: Implement me!

		byte[] encrypted = new byte[plain.length];
	

		for (int i = 0; i < plain.length; i++)
			encrypted[i] = (byte) (key[i % key.length] ^ plain[i]);
		
		byte[] padded_encrypted = addPadding(encrypted);
	
		return padded_encrypted;
	}

	/**
	 * Decrypts the given byte array and returns the decrypted and unpadded data
	 * in a new array.
	 * 
	 * @param cypher
	 *            The encrypted data. After Decryption, this array contains the
	 *            plain data.
	 * @return The length of the plain data in the array. This may be smaller
	 *         than the length of the array, since padding might be removed.
	 * @throws PaddingException
	 *             Thrown if either the length of the input array is not a
	 *             multiple of the block size or if the padding data contains an
	 *             error.
	 */
	public byte[] decrypt(byte[] cipher) throws PaddingException {
		// TODO: Implement me!
		
		byte[] unpadded = removePadding(cipher);
		byte[] plain = new byte[unpadded.length];
		
		for (int i = 0; i < plain.length; i++)
			plain[i] = (byte) (key[i % key.length] ^ unpadded[i]);
		
		
		return plain;
	}

	/**
	 * Generates a signature for the given content.
	 * 
	 * @param content
	 *            The content to be signed.
	 * @return A new byte array containing the generated signature.
	 * @throws NoSuchAlgorithmException
	 *             Thrown if the chosen hash algorithm is not available on this
	 *             platform.
	 * @throws PaddingException
	 *             Thrown if an error occurs during padding the signature to
	 *             block size.
	 */
	public byte[] generateSignature(byte[] content)
			throws NoSuchAlgorithmException, PaddingException {
		// TODO: Implement me!

		MessageDigest md = MessageDigest.getInstance("SHA-256");
		md.update(content);
		byte[] signature = md.digest();
		return signature;
	}

	/**
	 * Tests whether the given signature is valid for the given content.
	 * 
	 * @param content
	 *            Content whose signature is to be verified (passed without the
	 *            signature)
	 * @param signature
	 *            Signature to be verified
	 * @return True in case the signature is valid for the given content, false
	 *         otherwise.
	 * @throws NoSuchAlgorithmException
	 *             Thrown if the chosen hash algorithm is not available on this
	 *             platform.
	 * @throws PaddingException
	 *             Thrown if an error occurs during padding the signature to
	 *             block size.
	 */
	public boolean checkSignature(byte[] content, byte[] signature)
			throws NoSuchAlgorithmException, PaddingException {
		// TODO: Implement me!
		MessageDigest md = MessageDigest.getInstance("SHA-256");
		md.update(content);
		byte[] my_signature = md.digest();
	
		if (my_signature.length != signature.length)
			return false;

		for (int i = 0; i < signature.length; i++) {
			if (my_signature[i] != signature[i])
				return false;
		}
		
		return true;
	}

	/**
	 * Returns the length of the signature produced by this algorithm. Note
	 * that, depending on the signature scheme, the length of a signature may
	 * not always be constant.
	 * 
	 * @param data
	 *            Data to determine the signature length for/from
	 * @param offset
	 *            Offset of data in the array
	 * @param length
	 *            Length of data in the array
	 * @return The size (in bytes) of the signature data
	 */
	public int getSignatureLength(byte[] data, int offset, int length) {
		// TODO: Implement me!
		
		
		
		
		return  32;
	}

	// AUXILIAR METHODS ADDED

	public static void printBytes(byte[] data) {
		for (byte b : data)
			System.out.print(b + " ");
		System.out.println("");
	}

	private void fillArray(byte[] array, int ini, int padding) {
		for (int i = ini; i < (ini + padding); i++) {
			array[i] = (byte) padding;
		}
	}
}
