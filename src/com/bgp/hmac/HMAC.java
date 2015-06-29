package com.bgp.hmac;

import java.sql.Timestamp;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import org.apache.commons.codec.binary.Hex;
import com.bgp.consts.BGPConsts;

/**
 * Generate HMAC-SHA1 string, signed with a secret key
 * @author Ayoub
 * 
 */
public class HMAC {
    private String inputValue;
    private String blob;
    private Timestamp timeOfHash;
    
    /**
     * Default ctor
     */
    public HMAC() {
        inputValue = "";
        blob = "";
        timeOfHash = null;
    }
    
    /**
     * Secondary ctor
     */
    public HMAC(String input) {
        inputValue = input;
        blob = "";
        timeOfHash = null;
    }
    
    /**
     * Return the hmac
     * @param key string 
     */
    public void hmac(String key) {
        blob = staticHMAC(inputValue, key);
    }
    
    /**
     * Return the hmac
     * @param key
     */
    public void hmac(SecretKey key) {
        blob = staticHMAC(inputValue, key);
    }
    /**
     * Method that return hmac signed by key of input value
     * @param value input value
     * @param key key to sign hmac
     * @return String
     */
    public void hmac(String value, String key) {
        blob = staticHMAC(value, key);
    }
    
    /**
     * method that return hmac signed by key of input value
     * @param value input value
     * @param key Secret key
     * @return String
     */
    public void hmac(String value, SecretKey key) {
        blob = staticHMAC(value, key);
    }
    
    /**
     * Return the blob of data
     * @return String
     */
    public String getBlob() {
        return blob;
    }
    
    /**
     * Return the timestamp of hash
     * @return
     */
    public Timestamp getTimestampOfHash() {
        return timeOfHash;
    }
    
    /**
     * Add timestamp to the input value, this is optional but is a secure way to avoid replay attack
     */
    public void addTimestamp(Timestamp time) {
        timeOfHash = time;
        inputValue += time;
    }
     
    /**
     * Static method that return hmac signed by key of input value
     * @param value input value
     * @param key key to sign hmac
     * @return String
     */
    public static String staticHMAC(String value, String key) {
        try {
            // get an hmac-sha1 from the raw key bytes
            byte[] keyBytes = key.getBytes();
            SecretKey signinKey = new SecretKeySpec(keyBytes, "HmacSHA1");
            
            Mac mac = Mac.getInstance("HmacSHA1");
            mac.init(signinKey);
            
            // compute the hmac on input
            byte[] rawHmac = mac.doFinal(value.getBytes());
            
            // convert raw byte to hex
            byte[] hexByte = new Hex().encode(rawHmac);
            
            return new String(hexByte, "UTF-8");
            
        } catch(Exception e) {
            e.printStackTrace();
        }
        
        return null;
    }
    
    /**
     * Static method that return hmac signed by key of input value
     * @param value input value
     * @param key Secret key
     * @return String
     */
    public static String staticHMAC(String value, SecretKey key) {
        try {
            
            Mac mac = Mac.getInstance("HmacSHA1");
            mac.init(key);
            
            // compute the hmac on input
            byte[] rawHmac = mac.doFinal(value.getBytes());
            
            // convert raw byte to hex
            byte[] hexByte = new Hex().encode(rawHmac);
            
            return new String(hexByte, "UTF-8");
            
        } catch(Exception e) {
            e.printStackTrace();
        }
        return null;
    }
    
    public static byte[] generateMac(byte[] cipher, SecretKey key) throws Exception {
        Mac sha256Mac = Mac.getInstance(BGPConsts.HMAC_ALGORITHM);
        sha256Mac.init(key);
        return sha256Mac.doFinal(cipher);
    }

    /**
     * Return current timestamp
     * @return Timestamp
     */
    public static Timestamp currentTimeStamp() {
        return new Timestamp(new java.util.Date().getTime());
    }
}
