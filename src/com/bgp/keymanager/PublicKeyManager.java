package com.bgp.keymanager;

import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import org.apache.commons.codec.binary.Base64;

/**
 * Class that manipulate public keys
 * @author ayoub
 *
 */
public class PublicKeyManager {
    
    /**
     * Convert public key to string
     * @param publicKey rsa public key
     * @return string 
     * @throws InvalidKeySpecException
     * @throws NoSuchAlgorithmException
     */
    public static String convertToString(PublicKey publicKey) throws InvalidKeySpecException, NoSuchAlgorithmException {
        KeyFactory fact = KeyFactory.getInstance("RSA");
        X509EncodedKeySpec spec = fact.getKeySpec(publicKey, X509EncodedKeySpec.class);
        return Base64.encodeBase64String(spec.getEncoded());
    }
    
    /**
     * Convert string to public key
     * @param stringKey string public key 
     * @return Public key object
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeySpecException
     */
    public static PublicKey convertToKey(String stringKey) throws NoSuchAlgorithmException, InvalidKeySpecException {
        byte[] data = Base64.decodeBase64(stringKey);
        X509EncodedKeySpec spec = new X509EncodedKeySpec(data);
        KeyFactory fact = KeyFactory.getInstance("RSA");
        return fact.generatePublic(spec);
    }
    
    /**
     * Convert public key to bytes
     * @param key public key
     * @return bytes
     * @throws InvalidKeySpecException
     * @throws NoSuchAlgorithmException
     */
    public static byte[] convertToByte(PublicKey key) throws InvalidKeySpecException, NoSuchAlgorithmException {
        KeyFactory fact = KeyFactory.getInstance("RSA");
        X509EncodedKeySpec spec = fact.getKeySpec(key, X509EncodedKeySpec.class);
        return spec.getEncoded();
    }
    
    /**
     * Convert bytes into public key
     * @param key bytes
     * @return public key
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeySpecException
     */
    public static PublicKey convertToKey(byte[] key) throws NoSuchAlgorithmException, InvalidKeySpecException {
        X509EncodedKeySpec spec = new X509EncodedKeySpec(key);
        KeyFactory fact = KeyFactory.getInstance("RSA");
        return fact.generatePublic(spec);
    }
}
