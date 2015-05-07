#BGP (Bit Good Privacy)
BGP is a homemade GPG implementation in java.
##How PGP works
PGP combines some of the best features of both conventional and public key cryptography. PGP is a hybrid cryptosystem. When a user encrypts plaintext with PGP, PGP first compresses the plaintext. Data compression saves modem transmission time and disk space and, more importantly, strengthens cryptographic security. Most cryptanalysis techniques exploit patterns found in the plaintext to crack the cipher. Compression reduces these patterns in the plaintext, thereby greatly enhancing resistance to cryptanalysis. (Files that are too short to compress or which don't compress well aren't compressed.)  
PGP then creates a session key, which is a one-time-only secret key. This key is a random number generated from the random movements of your mouse and the keystrokes you type. This session key works with a very secure, fast conventional encryption algorithm to encrypt the plaintext; the result is ciphertext. Once the data is encrypted, the session key is then encrypted to the recipient's public key. This public key-encrypted session key is transmitted along with the ciphertext to the recipient.   
Decryption works in the reverse. The recipient's copy of PGP uses his or her private key to recover the temporary session key, which PGP then uses to decrypt the conventionally-encrypted ciphertext.   
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

