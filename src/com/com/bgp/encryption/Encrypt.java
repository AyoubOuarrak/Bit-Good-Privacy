package com.bgp.encryption;
import java.security.PublicKey;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
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
        encryptSessionKey();
    }
    
    /**
     * Secondary Ctor. 
     * @param pk public key
     * @param sK session Key
     * @throws Exception
     */
    public Encrypt(PublicKey pk, SecretKey sK) throws Exception {
        publicKey = pk;
        sessionKey = sK;
        encryptSessionKey();
    }

    /**
     * Generate a session key
     * @param bits lenght of the key
     * @return session key
     * @throws Exception
     * 
     */
    public static SecretKey generateSessionKey(int bits)  throws Exception {
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");

        keyGen.init(bits);
        SecretKey SK = keyGen.generateKey();
        return SK;
    }
    
    /**
     * Generate a 128 session key
     * @return
     * @throws Exception
     */
    public static SecretKey generateSessionKey() throws Exception {
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");

        keyGen.init(128);
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
        Cipher c = Cipher.getInstance("AES");
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
     * @throws Exception
     */
    private void encryptSessionKey() throws Exception  {
        
        Cipher rsaCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        rsaCipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] encryptedSK = rsaCipher.doFinal(sessionKey.getEncoded());

        SecretKey encodedEncryptedSK = new SecretKeySpec(encryptedSK, 0, encryptedSK.length, "AES");
        this.encryptedSessionKey = encodedEncryptedSK;
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
     * Return the session key
     * @return
     */
    public SecretKey getSessionKey() {
        return sessionKey;
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