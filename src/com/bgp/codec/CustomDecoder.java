package com.bgp.codec;

public class CustomDecoder {
    private static DecodingMethod customDecoder = null;
    
    /**
     * class not instantiable
     */
    private CustomDecoder() {
    }
    
    /**
     * Set custom decoder
     * 
     * @param method DecodingMethod
     */
    public static void set(DecodingMethod method) {
        customDecoder = method;
    }
    
    /**
     * Get custom decoder
     * 
     * @param method DecodingMethod
     */
    public static DecodingMethod get() {
        return customDecoder;
    }
    
    /**
     * Control if the custom decoder is enable or nat
     * 
     * @return boolean
     */
    public static boolean isEnable() {
        return customDecoder != null;
    }
}
