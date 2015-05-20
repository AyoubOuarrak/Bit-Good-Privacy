package com.bgp.encryption;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.codec.binary.Base64;

import com.bgp.codec.EncodingMethod;
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
    private SecretKey encryptedSessionKey;
    private PublicKey publicKey;
    private EncodingMethod customEncoding = null;

    /**
     * Ctor. Generate a session key, then encrypt the generated session key with
     * the public key
     * 
     * @param pk public key
     * @throws Exception 
     */
    public Encrypt(PublicKey pk) throws Exception {
        publicKey = pk;
        sessionKey = generateSessionKey(128);
        encryptedSessionKey = encryptSessionKey();
    }
    
    /**
     * Ctor. Generate a session key, then encrypt the generated session key with
     * the public key
     * @param pk public key
     * @param bits bits of session key
     * @throws Exception
     */
    public Encrypt(PublicKey pk, int bits) throws Exception {
        publicKey = pk;
        sessionKey = generateSessionKey(bits);
        encryptedSessionKey = encryptSessionKey();
    }

    /**
     * Generate a 128 bit session key
     * 
     * @return session key
     */
    private static SecretKey generateSessionKey(int bits) {
        KeyGenerator keyGen = null;

        try {
            keyGen = KeyGenerator.getInstance("AES/CBC/PKCS5PAdding");
        } catch (NoSuchAlgorithmException e) {
 
            e.printStackTrace();
        }

        keyGen.init(bits);
        SecretKey SK = keyGen.generateKey();
        return SK;
    }

    /**
     * Encrypt string and return the encrypted string
     * 
     * @param plainText string to encrypt
     * @return encrypted string
     */
    public String encrypt(String plainText) throws Exception {
        // compress the string to encrypt
        byte[] compressedData = Gzip.compress(plainText);

        // encrypt data with the unencrypted session key
        Cipher c = Cipher.getInstance("AES/CBC/PKCS5PAdding");
        c.init(Cipher.ENCRYPT_MODE, sessionKey);
        byte[] encodedData = c.doFinal(compressedData);

        // encode the encrypted data as a string
        String cipherText;
        if(customEncoding == null) cipherText = new Base64().encodeAsString(encodedData);
        else cipherText = customEncoding.encodeAsString(encodedData);
        
        return cipherText;
    }

    /**
     * Encrypt session key with public RSA key
     * 
     * @param sessionKey unencrypted session key
     * @return encrypted session key
     * @throws NoSuchPaddingException 
     * @throws NoSuchAlgorithmException 
     * @throws InvalidKeyException 
     * @throws BadPaddingException 
     * @throws IllegalBlockSizeException 
     */
    private SecretKey encryptSessionKey() throws Exception {
        Cipher rsaCipher = Cipher.getInstance("RSA");
        rsaCipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] encryptedSK = rsaCipher.doFinal(sessionKey.getEncoded());

        SecretKey encodedEncryptedSK = new SecretKeySpec(encryptedSK, 0, encryptedSK.length, "AES/CBC/PKCS5PAdding");
        return encodedEncryptedSK;
    }

    /**
     * Return the encrypted session key
     * 
     * @return encrypted session key
     */
    public SecretKey getEncryptedSessionKey() {
        return encryptedSessionKey;
    }
    
    /**
     * Sets a custom encoding method to be used instead of the
     * default from Apache Common Codec lib.
     * 
     * @param method the method
     */
    public void setCustomEncoding(EncodingMethod method){
    	this.customEncoding = method;
    }
}
