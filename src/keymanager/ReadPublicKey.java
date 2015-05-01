package keymanager;

import java.io.IOException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;

/**
 * Class that read public key from file
 * 
 * @author ayoub
 *
 */
public class ReadPublicKey {
    private String publicKeyFilename;
    private PublicKey publicKey;
    
    /**
     * Default ctor
     * @param filename path of the public key
     */
    public ReadPublicKey(String filename) {
       publicKeyFilename = filename;
    }
    
    /**
     *  Read public key and save it
     * @return
     * @throws IOException
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeySpecException
     */
    public void readPublicKey() throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        X509EncodedKeySpec publicSpec = new X509EncodedKeySpec(ReadFileBytes.read(publicKeyFilename));
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        publicKey =  keyFactory.generatePublic(publicSpec);       
    }
    
    /**
     * Return the public key
     * @return public key
     */
    public PublicKey getPublicKey() {
        return publicKey;
    }
}
