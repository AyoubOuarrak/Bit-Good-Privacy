package com.bgp.keymanager;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.codec.binary.Base64;

/**
 * Class that manipulate session keys
 * @author ayoub
 *
 */
public class SessionKeyManager {

    /**
     * Convert string to session key
     * @param key string key
     * @return secret key object
     */
    public static SecretKey convertToKey(String key) {
        byte[] encodedKey = Base64.decodeBase64(key);
        SecretKey sessionKey = new SecretKeySpec(encodedKey, 0, encodedKey.length, "AES");
        return sessionKey;
    }
    
    /**
     * Convert session key to string
     * @param key
     * @return
     */
    public static String convertToString(SecretKey key) {
        byte[] data = key.getEncoded();
        String sessionKey = Base64.encodeBase64String(data);
        return sessionKey;
    }
    
    /**
     * Convert key to bytes
     * @param key
     * @return
     */
    public static byte[] convertToByte(SecretKey key) {
        return key.getEncoded();
    }
    
    /**
     * convert bytes to key
     * @param key
     * @return
     */
    public static SecretKey convertToKey(byte[] key) {
        return new SecretKeySpec(key, 0, key.length, "AES");
    }
}
