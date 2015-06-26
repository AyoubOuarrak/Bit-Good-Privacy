package com.bgp.decryption;

import java.security.PrivateKey;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.codec.binary.Base64;

import com.bgp.codec.DecodingMethod;
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
    private DecodingMethod customDecoding = null;
    
    /**
     * Ctor. Decrypt the session key with the private key
     * 
     * @param pk private key
     * @throws Exception 
     */
    public Decrypt(PrivateKey pk, SecretKey crSK) throws Exception {
        privateKey = pk;
        cryptedSessionKey = crSK;
        decryptSessionKey();
    }
    
    /**
     * Decrypt string and return the decrypted string
     * 
     * @param cipherText encrypted string to decrypt
     * @return decrypted string
     */
    public String decrypt(String cipherText) throws Exception {
        byte[] decodedCipherText;
        
        String iv64 = cipherText.substring(0, 16*2);
        String cipherText64 = cipherText.substring(16*2);
        byte[] iv;
        IvParameterSpec ivSpec;
        
        if(customDecoding == null) {
            iv = Base64.decodeBase64(iv64);
            ivSpec = new IvParameterSpec(iv);
            decodedCipherText = Base64.decodeBase64(cipherText64);
        }
        else {
            iv = customDecoding.decode(iv64);
            ivSpec = new IvParameterSpec(iv);
            decodedCipherText = customDecoding.decode(cipherText64);
        }
        
        // decrypt data using the original session key
        Cipher c = Cipher.getInstance("AES/CBC/PKCS5Padding");
        c.init(Cipher.DECRYPT_MODE, sessionKey, ivSpec);
        byte[] compressedPlainText = c.doFinal(decodedCipherText);
        
        // decompress data
        //String plainText = Gzip.decompress(compressedPlainText);
        return Gzip.decompress(compressedPlainText);
    }

    /**
     * Decrypt session key with private RSA key
     * 
     * @param sessionKey crypted session key
     * @return decrypted session key
     */
    private void decryptSessionKey() throws Exception {
        Cipher rsaCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        rsaCipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] SK = rsaCipher.doFinal(cryptedSessionKey.getEncoded());

        SecretKey originalSessionKey = new SecretKeySpec(SK, 0, SK.length, "AES");
        this.sessionKey = originalSessionKey;
    }
    
    /**
     * Return the session key
     * @return
     */
    public SecretKey getSessionKey() {
        return sessionKey;
    }
    
    /**
     * Sets a custom decoding method to be used instead of the
     * default from Apache Common Codec lib.
     * 
     * @param method the method
     */
    public void setCustomDecoding(DecodingMethod method){
    	this.customDecoding = method;
    }
}
