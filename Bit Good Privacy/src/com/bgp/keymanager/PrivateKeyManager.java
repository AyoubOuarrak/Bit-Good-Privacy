package com.bgp.keymanager;

import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Arrays;

import org.apache.commons.codec.binary.Base64;

/**
 * Class that manipulate private keys
 * @author ayoub
 *
 */
public class PrivateKeyManager {
    
    /**
     * Convert private key to string
     * @param privateKey private key object
     * @return string private key
     * @throws InvalidKeySpecException
     * @throws NoSuchAlgorithmException
     */
    public static String convertToString(PrivateKey privateKey) throws InvalidKeySpecException, NoSuchAlgorithmException {
        KeyFactory fact = KeyFactory.getInstance("RSA");
        PKCS8EncodedKeySpec spec = fact.getKeySpec(privateKey, PKCS8EncodedKeySpec.class);
        byte[] data = spec.getEncoded();
        String key = Base64.encodeBase64String(data);
        Arrays.fill(data, (byte) 0);
        return key;
    }
    
    /**
     * Convert String to private key
     * @param stringKey
     * @return
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeySpecException
     */
    public static PrivateKey convertToKey(String stringKey) throws NoSuchAlgorithmException, InvalidKeySpecException {
        byte[] data = Base64.decodeBase64(stringKey);
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(data);
        KeyFactory fact = KeyFactory.getInstance("RSA");
        PrivateKey privK = fact.generatePrivate(spec);
        Arrays.fill(data, (byte) 0);
        return privK;
    }
    
    /**
     * Convert to bytes
     * @param key private key
     * @return bytes
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeySpecException
     */
    public static byte[] convertToByte(PrivateKey key) throws NoSuchAlgorithmException, InvalidKeySpecException {
        KeyFactory fact = KeyFactory.getInstance("RSA");
        PKCS8EncodedKeySpec spec = fact.getKeySpec(key, PKCS8EncodedKeySpec.class);
        return spec.getEncoded();
    }
    
    /**
     * Convert to key from bytes
     * @param key bytes
     * @return private key
     * @throws InvalidKeySpecException
     * @throws NoSuchAlgorithmException
     */
    public static PrivateKey convertToKey(byte[] key) throws InvalidKeySpecException, NoSuchAlgorithmException {
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(key);
        KeyFactory fact = KeyFactory.getInstance("RSA");
        PrivateKey privK = fact.generatePrivate(spec);
        return privK;
    }
}
