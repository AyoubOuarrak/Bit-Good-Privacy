package com.bgp.consts;

public class BGPConsts {
    public static final String CIPHER_PADDING_ALGORITHM = "AES/CBC/PKCS5Padding";
    public static final String CIPHER_ALGORITHM = "AES";
    public static final String RANDOM_ALGORITHM = "SHA1PRNG";
    public static final int AES_KEY_LENGTH = 128;
    public static final int IV_LENGTH = 16;
    
    public static final int PBE_SALT_LENGTH = AES_KEY_LENGTH;
    public static final int PBE_ITERATION_COUNT = 10000;
    public static final String PBE_ALGORTIHM = "PBKDF2WithHmacSHA1";
    
    public static final String HMAC_ALGORITHM = "HmacSHA256";
    public static final int HMAC_KEY_LENGTH = 256;
}
