package com.bgp.codec;


/**
 * Interface for custom encoding method callback.
 * 
 * @author Giuseppe Petrosino
 *
 */
public interface EncodingMethod {
	public String encodeAsString(byte[] bytes);
}
