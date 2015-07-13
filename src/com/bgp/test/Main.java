package com.bgp.test;

import com.bgp.decryption.Decrypt;
import com.bgp.encryption.Encrypt;
import com.bgp.generator.KeyGenerator;

public class Main {

    public static void main(String[] args) {
        try {
            KeyGenerator serverG = new KeyGenerator();
            KeyGenerator clientG = new KeyGenerator();
            
            Encrypt clientEncrypter = new Encrypt(serverG.getPublicKey());
            String cipherText = clientEncrypter.encrypt("a");
            
            
            Decrypt serverDecrytper  = new Decrypt(serverG.getPrivateKey(), 
                                                   clientEncrypter.getEncryptedSessionKey());
            
            System.out.println("Client Cipher text : " + cipherText);
            System.out.println("IV : " + clientEncrypter.getIV());
            System.out.println(serverDecrytper.decrypt(cipherText));
            
            
        } catch (Exception e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
    }

}


