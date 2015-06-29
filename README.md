#Bit Good Privacy 
Multiplatform Java library for encryption/decryption using symmetric and asymmetric cryptography (similar to PGP). BGP is very simple to use, few lines of code and you have encrypted/decrypted your data without the need of losing your mental health.
        
##How BGP works
BGP combines some of the best features of both conventional and public key cryptography. BGP is a hybrid cryptosystem. When a user encrypts plaintext with BGP, BGP first compresses the plaintext. Data compression saves modem transmission time and disk space and, more importantly, strengthens cryptographic security. Most cryptanalysis techniques exploit patterns found in the plaintext to crack the cipher. Compression reduces these patterns in the plaintext, thereby greatly enhancing resistance to cryptanalysis. (Files that are too short to compress or which don't compress well aren't compressed.)  
BGP then creates a session key, which is a one-time-only secret key. This session key works with a very secure, fast conventional encryption algorithm to encrypt the plaintext; the result is ciphertext. Once the data is encrypted, the session key is then encrypted to the recipient's public key. This public key-encrypted session key is transmitted along with the ciphertext and IV to the recipient.   
Decryption works in the reverse. The recipient's copy of BGP uses his or her private key to recover the temporary session key, which BGP then uses to decrypt the conventionally-encrypted ciphertext.   
The combination of the two encryption methods combines the convenience of public key encryption with the speed of conventional encryption. Conventional encryption is about 1, 000 times faster than public key encryption. Public key encryption in turn provides a solution to key distribution and data transmission issues. Used together, performance and key distribution are improved without any sacrifice in security.  
    
##Usage of BGP
###Key generator
```java
 // generate 1024 bit  RSA private, public keys
 KeyGenerator generator = new KeyGenerator();
 
 KeyGenerator generator = new KeyGenerator(2048, "RSA");
```
   
###Encryption
```java
// BGP encrypt data using the public key
Encrypt encrypter = new Encrypt(publicKey);
String cipherText = encrypter.encrypt("some text");
```
   
###Decryption
```java
// The encrypter need the private key and the encrypted session key
Decrypt decrypter = new Decrypt(privateKey, encryptedSessionKey);

String decryptedText = decrypter.decrypt(cipherText);
```
  
###Save key pair into file
```java
// this function save into file the public and private keys
generator.saveKeyPair();
```
   
###Load key pair from file
```java
// this function load from file the public and private keys
KeyPair keys = KeyGenerator.loadKeyPair();

// get public key
PublicKey pubK = keys.getPublic();

//get private key
PrivateKey piK = keys.getPrivate();
```

###HMAC Autentication
```java
 // create a hmac object passing the blob of data
 HmacSHA1 hmac = new HmacSHA1("hola " + "chica");
 
 // add timestamp to avoid replay attack
 hmac.addTimestamp(HmacSHA1.currentTimeStamp());
 
 // generate the hmac, passing a SecretKey obj
 String hhhmac = hmac.hmac(key);
```
    
##Example
```java
import com.bgp.decryption.Decrypt;
import com.bgp.encryption.Encrypt;
import com.bgp.generator.KeyGenerator;

public class Main {
   public static void main(String[] args) {
        try {
            // generate a 1024 default RSA keys for client and server
            KeyGenerator serverG = new KeyGenerator();
            KeyGenerator clientG = new KeyGenerator();
            
            // initialize the client encrypter using the server public key
            Encrypt clientEncrypter = new Encrypt(serverG.getPublicKey());
            
            // encrypt your data
            String cipherText = clientEncrypter.encrypt("hola");
            
            // In the other side the server initialize the decrypter using the private key, and the client 
            // encrypted session key
            Decrypt serverDecrytper  = new Decrypt(serverG.getPrivateKey(), 
                                                   clientEncrypter.getEncryptedSessionKey());
                                                   
            System.out.println("Cipher text : " + cipherText);
            System.out.println("Plain text : " + serverDecrytper.decrypt(cipherText));
            
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

}
```
As you can see, the usage of BGP is very simple and very secure.
   
##Installation
### Java SE / EE
Add the jar of BGP in your buildpath, if you want to use BGP in a server side, (for example tomcat) you need to add the jar also in the lib folder of your project.   
   
### Android
Add the jar of BGP in your app/libs folder, and rebuild gradle.
   
##License
   
The MIT License (MIT) 

Copyright © 2015 Ayoub Ouarrak  
   
Permission is hereby granted, free of charge, to any person obtaining a copy   
of this software and associated documentation files (the "Software"), to deal   
in the Software without restriction, including without limitation the rights   
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell   
copies of the Software, and to permit persons to whom the Software is   
furnished to do so, subject to the following conditions:   
   
The above copyright notice and this permission notice shall be included in   
all copies or substantial portions of the Software.   
   
THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR   
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,   
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE   
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER   
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,   
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN   
THE SOFTWARE.     
   
![](https://s3.amazonaws.com/f.cl.ly/items/1I0Y1d0e1S2M1t3x3s2o/1432609520_valenticons-19.png) 
