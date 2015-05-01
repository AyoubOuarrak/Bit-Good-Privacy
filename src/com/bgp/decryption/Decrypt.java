package com.bgp.decryption;

import java.security.PrivateKey;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.codec.binary.Base64;

import com.bgp.compression.Gzip;

/**
 * Class Decrypt. First, we decrypt the session key using the private key, then we user
 * the decrypted session key to decrypt the encrypted data.
 * 
 * @author Ayoub Ouarrak
 *
 */
public class Decrypt {
    private PrivateKey privateKey;
    private SecretKey cryptedSessionKey; 
    private SecretKey sessionKey;
    
    /**
     * Ctor. Decrypt the session key with the private key
     * 
     * @param pk private key
     * @throws Exception 
     */
    public Decrypt(PrivateKey pk) throws Exception {
        privateKey = pk;
        sessionKey = decryptSessionKey();
    }
    
    /**
     * Decrypt string and return the decrypted string
     * 
     * @param cipherText encrypted string to decrypt
     * @return decrypted string
     */
    public String decrypt(String cipherText) throws Exception {
        byte[] decodedCipherText = new Base64().decode(cipherText);
        
        // decrypt data using the original session key
        Cipher c = Cipher.getInstance("AES");
        c.init(Cipher.DECRYPT_MODE, sessionKey);
        byte[] compressedPlainText = c.doFinal(decodedCipherText);
        
        // decompress data
        String plainText = Gzip.decompress(compressedPlainText);
        return plainText;
    }

    /**
     * Decrypt session key with private RSA key
     * 
     * @param sessionKey crypted session key
     * @return decrypted session key
     */
    private SecretKey decryptSessionKey() throws Exception {
        Cipher rsaCipher = Cipher.getInstance("RSA");
        rsaCipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] SK = rsaCipher.doFinal(cryptedSessionKey.getEncoded());

        SecretKey originalSessionKey = new SecretKeySpec(SK, 0, SK.length, "AES");
        return originalSessionKey;
    }
}
