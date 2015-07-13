package com.bgp.codec;

public class CustomEncoder {
    private static EncodingMethod customEncoder = null;
    
    /**
     * class not instantiable
     */
    private CustomEncoder() {   
    }
    
    /**
     * Set custom encoder
     * 
     * @param method EncodingMethod
     */
    public static void set(EncodingMethod method) {
        customEncoder = method;
    }
    
    /**
     * Get custom encoder
     * 
     * @param method EncodingMethod
     */
    public static EncodingMethod get() {
        return customEncoder;
    }
    
    /**
     * Control if the custom encoder is enable or nat
     * 
     * @return boolean
     */
    public static boolean isEnable() {
        return customEncoder != null;
    }
}
