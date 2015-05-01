package com.bgp.keymanager;

import java.io.IOException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;

/**
 * Class that read private key from file
 * 
 * @author ayoub
 *
 */
public class ReadPrivateKey {
    private String privateKeyFilename;
    private PrivateKey privateKey;
    
    /**
     * Default ctor
     * @param filename path of the private key
     */
    public ReadPrivateKey(String filename) {
       privateKeyFilename = filename;
    }
    
    /**
     *  Read private key and save it
     * @return
     * @throws IOException
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeySpecException
     */
    public void readPublicKey() throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(ReadFileBytes.read(privateKeyFilename));
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        privateKey =  keyFactory.generatePrivate(keySpec); 
    }
    
    /**
     * Return the public key
     * @return public key
     */
    public PrivateKey getPrivateKey() {
        return privateKey;
    }
}
