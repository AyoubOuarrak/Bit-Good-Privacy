package com.bgp.compression;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStreamReader;
import java.util.zip.GZIPInputStream;
import java.util.zip.GZIPOutputStream;
import javax.management.BadStringOperationException;

/**
 * Class for compression and decompression of strings
 * 
 * @author ayoub
 *
 */
public class Gzip {
    
    /**
     * Compress string and return a compressed array of bytes
     * 
     * @param str string to compress
     * @return array of bytes
     * @throws Exception
     */
    public static byte[] compress(String str) throws Exception {
        if (str == null || str.length() == 0) {
            throw new BadStringOperationException("string is empty or null");
        }

        ByteArrayOutputStream obj = new ByteArrayOutputStream();
        GZIPOutputStream gzip = new GZIPOutputStream(obj);
        gzip.write(str.getBytes("UTF-8"));
        gzip.close();

        return obj.toByteArray();
    }

    /**
     * Decompress the array of bytes and return the decompressed string
     * 
     * @param bytes
     *            Compressed array of bytes
     * @return decompressed string
     * @throws Exception
     */
    public static String decompress(byte[] bytes) throws Exception {
        GZIPInputStream gis = new GZIPInputStream(new ByteArrayInputStream(bytes));
        BufferedReader bf = new BufferedReader(new InputStreamReader(gis, "UTF-8"));
        String outStr = "";
        String line;
        
        while ((line = bf.readLine()) != null) {
            outStr += line;
        }
        
        return outStr;
    }
}
