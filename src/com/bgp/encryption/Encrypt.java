package com.bgp.encryption;

import java.security.PublicKey;
import java.security.SecureRandom;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.apache.commons.codec.binary.Base64;
import com.bgp.codec.CustomEncoder;
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
    private SecretKey cryptedSessionKey;
    private PublicKey publicKey;
    private byte[] iv;

    /**
     * Ctor. Generate a session key, then encrypt the generated session key with
     * the public key
     * 
     * @param pk public key
     * @throws Exception 
     */
    public Encrypt(PublicKey pk) throws Exception {
        publicKey = pk;
        sessionKey = generateSessionKey();
        iv = generateIV();
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
        iv = generateIV();
        encryptSessionKey();
    }

    /**
     * Generate a session key
     * @param bits length of the key
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
     * @return iv : encrypted string
     */
    public String encrypt(String plainText) throws Exception {
        // compress the string to encrypt and generate the initialization vector (iv)
        byte[] compressedData = Gzip.compress(plainText);
        
        // encrypt data with the unencrypted session key
        Cipher c = Cipher.getInstance("AES/CBC/PKCS5Padding");
        c.init(Cipher.ENCRYPT_MODE, sessionKey, new IvParameterSpec(this.iv));
        
        this.iv = c.getIV();
        byte[] encodedData = c.doFinal(compressedData);

        // encode the encrypted data as a string
        String civ;
        
        if(CustomEncoder.isEnable()) 
            civ = CustomEncoder.get().encodeAsString(this.iv) + ":" + CustomEncoder.get().encodeAsString(encodedData);    
        else 
            civ = new Base64().encodeAsString(this.iv) + ":" + new Base64().encodeAsString(encodedData);
        
        return civ;
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
        this.cryptedSessionKey = encodedEncryptedSK;
    }

    /**
     * Return the encrypted session key
     * 
     * @return encrypted session key
     */
    public SecretKey getEncryptedSessionKey() {
        return cryptedSessionKey;
    }
    
    /**
     * Return the session key
     *
     * @return SecretKey
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
    	CustomEncoder.set(method);
    }
    
    /**
     * Return the initialization vector
     * 
     * @return byte[]
     */
    public byte[] getIV() {
        return this.iv;
    }
    
    /**
     * Generate random initialization vector
     * 
     * @return byte[]
     */
    private byte[] generateIV() {
        try {
            SecureRandom random = SecureRandom.getInstance("SHA1PRNG");
            byte[] iv = new byte[16];
            random.nextBytes(iv);
            return iv;
            
        } catch(Exception e) {
            e.printStackTrace();
            return null;
        }
    }
}
