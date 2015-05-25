package com;

import com.bgp.decryption.Decrypt;
import com.bgp.encryption.Encrypt;
import com.bgp.generator.KeyGenerator;
import com.bgp.hmac.HmacSHA1;
import com.bgp.keymanager.PublicKeyManager;
import com.bgp.keymanager.SessionKeyManager;


public class Main {
    public static void main(String[] args) {
        KeyGenerator serverGen = null;
        KeyGenerator clientGen = null;
        Encrypt serverEncrypter = null;
        Encrypt clientEncrypter = null;
        
        try {
            serverGen = new KeyGenerator();
            clientGen = new KeyGenerator();
            
            serverEncrypter = new Encrypt(clientGen.getPublicKey());  
            clientEncrypter = new Encrypt(serverGen.getPublicKey()); 
            
        } catch(Exception e) {
            e.printStackTrace();
        }
        
        Decrypt serverDecrypter = null;
        Decrypt clientDecrypter = null;
        
        try {
            serverDecrypter = new Decrypt(serverGen.getPrivateKey(), clientEncrypter.getEncryptedSessionKey());
            clientDecrypter = new Decrypt(clientGen.getPrivateKey(), serverEncrypter.getEncryptedSessionKey());
            
            System.out.println("====== Encryption ======");
            System.out.println("PLAIN : hola");
            System.out.println("CIPHER: " + clientEncrypter.encrypt("hola"));
            //System.out.println("PUB: " + PublicKeyManager.convertToByte(serverGen.getPublicKey()));
            System.out.println("SESSION:" + SessionKeyManager.convertToString(clientEncrypter.getSessionKey()));
            
            System.out.println("====== Decryption ======");
            System.out.println("DECRPT: " + serverDecrypter.decrypt(clientEncrypter.encrypt("hola")));
            System.out.println("SESSION: " +SessionKeyManager.convertToString(serverDecrypter.getSessionKey()) );
            
            System.out.println("========== HMAC =========");
            HmacSHA1 hmac = new HmacSHA1("hola " + "prova1");
            hmac.addTimestamp(HmacSHA1.currentTimeStamp());
            hmac.hmac(clientEncrypter.getSessionKey());
            System.out.println(hmac.getBlob());
            
            HmacSHA1 hmac2 = new HmacSHA1("hola " + "prova1");
            hmac2.addTimestamp(hmac.getTimestampOfHash());
            hmac2.hmac(serverDecrypter.getSessionKey());
            System.out.println(hmac2.getBlob());
            
        } catch (Exception e) {
            e.printStackTrace();
        }
        
        
    }
    
}
