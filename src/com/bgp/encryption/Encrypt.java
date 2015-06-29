package com.bgp.encryption;

import java.security.PublicKey;
import java.security.SecureRandom;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import com.bgp.android.PrngFixes;
import com.bgp.codec.EncodingMethod;
import com.bgp.compression.Gzip;
import com.bgp.consts.BGPConsts;
import com.bgp.hmac.HMAC;
import com.bgp.keystore.SafeStore;

/**
 * Class Encrypt. First, we create a session key, we encrypt the data with the
 * session key and, finally, we encrypt the session key with the RSA public key.
 * 
 * @author Ayoub Ouarrak
 *
 */
public class Encrypt {
    SafeStore safeStore;
    private SecretKey sessionKey;
    private SecretKey cryptedSessionKey;
    private PublicKey publicKey;

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
     * 
     * @return session key
     * @throws Exception
     * 
     */
    public static SecretKey generateSessionKey()  throws Exception {
        if(System.getProperty("java.vm.name").equalsIgnoreCase("Dalvik")) {
            synchronized (PrngFixes.class) {
                PrngFixes.apply();
            }
        }
        
        KeyGenerator keyGen = KeyGenerator.getInstance(BGPConsts.CIPHER_ALGORITHM);

        keyGen.init(BGPConsts.AES_KEY_LENGTH);
        SecretKey SK = keyGen.generateKey();
        return SK;
    }
    
    public SafeStore encrypt(String plain) throws Exception {
        return encrypt(plain.getBytes("UTF-8"));
    }

    /**
     * Encrypt string and return the encrypted string
     * 
     * @param plainText string to encrypt
     * @return SafeStore
     */
    public SafeStore encrypt(byte[] plainText) throws Exception {
        // compress the string to encrypt and generate the initialization vector (iv)
        byte[] compressedData = Gzip.compress(plainText);
        
        // encrypt data with the unencrypted session key
        Cipher c = Cipher.getInstance(BGPConsts.CIPHER_PADDING_ALGORITHM);
        byte[] iv = generateIV(c.getBlockSize());
        c.init(Cipher.ENCRYPT_MODE, sessionKey, new IvParameterSpec(iv));
        
        iv = c.getIV();
        byte[] encodedData = c.doFinal(compressedData);
        byte[] civ = SafeStore.concat(iv, encodedData);
        byte[] mac = HMAC.generateMac(civ, cryptedSessionKey);
        
        safeStore.set(encodedData, iv, mac);
        return this.safeStore;
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

        SecretKey encodedEncryptedSK = new SecretKeySpec(encryptedSK, 0, encryptedSK.length, BGPConsts.CIPHER_ALGORITHM);
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
    	safeStore.setCustomEncoding(method);
    }
    
    /**
     * Generate a random initialization vector of 16 byte
     * 
     * @return byte[]
     */
    public byte[] generateIV(int bytes) {
        try {
            SecureRandom random = SecureRandom.getInstance(BGPConsts.RANDOM_ALGORITHM);
            byte[] iv = new byte[bytes];
            random.nextBytes(iv);
            return iv;
            
        } catch(Exception e) {
            e.printStackTrace();
            return null;
        }
    }
}
