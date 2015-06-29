package com.bgp.keystore;


import java.util.Arrays;
import org.apache.commons.codec.binary.Base64;
import com.bgp.codec.DecodingMethod;
import com.bgp.codec.EncodingMethod;

/**
 * Hold the iv, mac and the cipher text
 *
 */
public class SafeStore {
    private DecodingMethod customDecoding = null;
    private EncodingMethod customEncoding = null;
    
    private byte[] cipherText;
    private byte[] IV;
    private byte[] MAC;
    
    /**
     * Default ctor
     */
    public SafeStore() {
        
    }
    
    /**
     * Store a cipher text, iv and mac in the SafeStore
     * 
     * @param c cipher text
     * @param iv initialization vector
     * @param mac mac
     */
    public SafeStore(byte[] c, byte[] iv, byte[] mac) {
        this.cipherText = new byte[c.length];
        System.arraycopy(c, 0, this.cipherText, 0, c.length);
        
        this.IV = new byte[iv.length];
        System.arraycopy(iv, 0, this.IV, 0, iv.length);
        
        this.MAC = new byte[mac.length];
        System.arraycopy(iv, 0, this.IV, 0, mac.length);
    }
    
    /**
     * Parse the string containing iv:cipher:mac and store them in the SafeStore
     * 
     * @param IVandCipher String containing iv:cipher:mac
     */
    public SafeStore(String IVandCipher) {
        String[] civ = IVandCipher.split(":");
        if(civ.length != 3)
            throw new IllegalArgumentException("Cannot parse iv:cipher:mac");
        else {
            if(customDecoding == null) {
                this.IV = Base64.decodeBase64(civ[0]);
                this.MAC =  Base64.decodeBase64(civ[1]);
                this.cipherText =  Base64.decodeBase64(civ[2]);
            }
        }
    }
    
    /**
     *  Store a cipher text, iv and mac in the SafeStore
     *  
     * @param c
     * @param iv
     * @param mac
     */
    public void set(byte[] c, byte[] iv, byte[] mac) {
        this.cipherText = new byte[c.length];
        System.arraycopy(c, 0, this.cipherText, 0, c.length);
        
        this.IV = new byte[iv.length];
        System.arraycopy(iv, 0, this.IV, 0, iv.length);
        
        this.MAC = new byte[mac.length];
        System.arraycopy(iv, 0, this.IV, 0, mac.length);
    }
    
    /**
     * Concatenate the initialization vector with the cipher text
     * 
     * @param iv initialization vector
     * @param cipher cipher text
     * @return byte[]
     */
    public static byte[] concat(byte[] iv, byte[] cipher) {
        byte[] combined = new byte[iv.length + cipher.length];
        
        System.arraycopy(iv, 0, combined, 0, iv.length);
        System.arraycopy(cipher, 0, combined, iv.length, cipher.length);
        
        return combined;
    }
    
    /**
     * Return the cipher text
     * 
     * @return byte[]
     */
    public byte[] getCipherText() {
        return this.cipherText;
    }
    
    /**
     * Return the initialization vector
     * 
     * @return byte[]
     */
    public byte[] getIv() {
        return this.IV;
    }
    
    /**
     * Return the mac
     * 
     * @return byte[]
     */
    public byte[] getMac() {
        return this.MAC;
    }
    
    public void setCustomEncoding(EncodingMethod customEncoding) {
        this.customEncoding = customEncoding;
    }
    
    public void setCustomDecoding(DecodingMethod customDecoding) {
        this.customDecoding = customDecoding;
    }
    
    /**
     * Encode the iv : mac : cipher text
     * 
     * @return base 64 string  iv:mac:ciphertext
     */
    @Override
    public String toString() {
        if(customEncoding == null) {
            String ivString = new Base64().encodeAsString(this.IV);
            String cipherString = new Base64().encodeAsString(this.cipherText);
            String macString = new Base64().encodeAsString(this.MAC);
            
            return String.format(ivString + ":" + macString + ":" + cipherString);
        } else {
            String ivString =  customEncoding.encodeAsString(this.IV);
            String cipherString = customEncoding.encodeAsString(this.cipherText);
            String macString =  customEncoding.encodeAsString(this.MAC);
            
            return String.format(ivString + ":" + macString + ":" + cipherString);
        }
    }
    
    @Override
    public boolean equals(Object obj) {
        if(this == obj) 
            return true;
        if(obj == null) 
            return false;
        if(getClass() != obj.getClass()) 
            return false;
        
        SafeStore other = (SafeStore) obj;
        if(!Arrays.equals(cipherText, other.cipherText))
            return false;
        if(!Arrays.equals(IV, other.IV))
            return false;
        if(!Arrays.equals(MAC, other.MAC))
            return false;
        
        return true;
    }
}
