import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;

import com.bgp.decryption.Decrypt;
import com.bgp.encryption.Encrypt;
import com.bgp.keymanager.KeyPairManager;

public class Main {

    public static void main(String[] args) {
        // generate rsa keys
        try {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
            kpg.initialize(1024);
            KeyPair kp = kpg.genKeyPair();
            Key publicKey = kp.getPublic();
            Key privateKey = kp.getPrivate();

            System.out.println("Public Key: " + getHexString(publicKey.getEncoded()));
            System.out.println("Private Key: " + getHexString(privateKey.getEncoded()));
            
            KeyPairManager.save(kp);
            System.out.println("keys saved");
            
            KeyPair loadedKeyPair = KeyPairManager.load("RSA");
            System.out.println("keys loaded");
            
            Key loadedPublicKey = loadedKeyPair.getPublic();
            Key loadedPrivateKey = loadedKeyPair.getPrivate();
            
            System.out.println("Public Key: " + getHexString(loadedPublicKey.getEncoded()));
            System.out.println("Private Key: " + getHexString(loadedPrivateKey.getEncoded()));
            
            System.out.println("----------- encrypter -----------");
            // encrypt
            Encrypt encrypter = new Encrypt(loadedKeyPair.getPublic());
            System.out.println("plaint text : [{name:lol}]");
            String cipherText = encrypter.encrypt("[{name:lol}]");
            System.out.println("cipher text :" + cipherText);
            
            
            System.out.println("----------- decrypter -----------");
            Decrypt decrypter = new Decrypt(loadedKeyPair.getPrivate(), encrypter.getEncryptedSessionKey());
            System.out.println("decrypted text: " + decrypter.decrypt(cipherText));
            
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static String getHexString(byte[] b) {
        String result = "";
        for (int i = 0; i < b.length; i++) {
            result += Integer.toString((b[i] & 0xff) + 0x100, 16).substring(1);
        }
        return result;
    }
}
