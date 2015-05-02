package com.bgp.generator;

import java.io.IOException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;

import com.bgp.keymanager.KeyPairManager;

/**
 * Class Generator, generate RSA key pair
 * @author ayoub
 *
 */
public class KeyGenerator extends KeyPairManager {
    private PublicKey publicKey;
    private PrivateKey privateKey;
    private KeyPair keyPair;
    
    /**
     * Default ctor
     */
    public KeyGenerator() {
        KeyPairGenerator kpg;
        try {
            kpg = KeyPairGenerator.getInstance("RSA");
            kpg.initialize(1024);
             
            keyPair = kpg.genKeyPair();
            publicKey = keyPair.getPublic();
            privateKey = keyPair.getPrivate();
            
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }   
    }
    
   /**
    * One paramenter ctor
    * @param bits bits of the key
    * @param algorithm RSA for default
    */
    public KeyGenerator(int bits, String algorithm) {
        KeyPairGenerator kpg;
        try {
            kpg = KeyPairGenerator.getInstance(algorithm);
            kpg.initialize(bits);
             
            keyPair = kpg.genKeyPair();
            publicKey = keyPair.getPublic();
            privateKey = keyPair.getPrivate();
            
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }   
    }
    
    /**
     * Return the public key
     * @return public key
     */
    public PublicKey getPublicKey() {
        return publicKey;
    }
    
    /**
     * Return the private key
     * @return private key
     */
    public PrivateKey getPrivateKey() {
        return privateKey;
    }
    
    /**
     * Return the key pair
     * @return
     */
    public KeyPair getKeyPair() {
        return keyPair;
    }
    
    /**
     * Save keyPair into file
     */
    public void saveKeyPair() {
        try {
            save(keyPair);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
    
    /**
     * Load keypair from file
     */
    public void load() {
        try {
            load("RSA");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (InvalidKeySpecException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}
