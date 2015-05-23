package com.bgp.codec;

/**
 * Interface for custom decoding method callback.
 * 
 * @author Giuseppe
 *
 */
public interface DecodingMethod {
	public byte[] decode(String str);
}
