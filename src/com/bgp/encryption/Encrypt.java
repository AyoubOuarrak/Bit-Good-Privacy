package com.bgp.encryption;

import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import org.apache.commons.codec.binary.Base64;
import com.bgp.compression.Gzip;

/**
 * Class Encrypt. First, we create a session key, we encrypt the data with the 
 * session key and, finally, we encrypt the session key with the RSA public key.
 * 
 * @author Ayoub Ouarrak
 *
 */
public class Encrypt {
	private SecretKey sessionKey;
	private PublicKey publicKey;
	private byte[] encryptedSessionKey;
	
	/**
	 * Ctor. Generate a session key, then encrypt the generated session key with the public key
	 * @param pk public key
	 */
	public Encrypt(PublicKey pk) {
		publicKey = pk;
		sessionKey = generateSessionKey();
		encryptedSessionKey = encryptSessionKey();
	}
	
	/**
	 * Generate a 128 bit session key
	 * @return session key
	 * @throws NoSuchAlgorithmException
	 */
	public static SecretKey generateSessionKey() {
		KeyGenerator keyGen = null;
		
		try {
			keyGen = KeyGenerator.getInstance("AES");
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		keyGen.init(128);
		SecretKey sessionKey = keyGen.generateKey();
		return sessionKey;
	}
	
	/**
	 * Encrypt string and return the encrypted string
	 * @param data string to encrypt
	 * @return encrypted string
	 * @throws Exception
	 */
	public String encrypt(String data) throws Exception {
		// compress the string to encrypt
		byte[] compressedData = Gzip.compress(data);
		
		Cipher c = Cipher.getInstance("AES");
		c.init(Cipher.ENCRYPT_MODE, sessionKey);
		byte[] encVal = c.doFinal(compressedData);

		String encryptedString = new Base64().encodeAsString(encVal);
	    return encryptedString;
	}
	
	/**
	 * Encrypt session key with public RSA key
	 * @param sessionKey unencrypted session key
	 * @return encrypted session key
	 */
	public byte[] encryptSessionKey() {
		byte[] encryptedSessionKey = null;
		
		try {
			Cipher rsaCipher = Cipher.getInstance("RSA");
			rsaCipher.init(Cipher.ENCRYPT_MODE, publicKey);
			encryptedSessionKey = rsaCipher.doFinal(sessionKey.getEncoded());
			
		} catch (Exception e) {
			e.printStackTrace();
		}
		
		return encryptedSessionKey;
	}
	
	/**
	 * Return the encrypted session key
	 * @return encrypted session key
	 */
	public byte[] getEncryptedSessionKey() {
		return encryptedSessionKey;
	}
}
