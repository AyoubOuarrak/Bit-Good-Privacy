package keymanager;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

public class ReadFileBytes {  
    
    /**
     * Read file and return the array of bytes
     * @param filename of the file
     * @return array of bytes
     * @throws IOException
     */
    public static byte[] read(String filename) throws IOException {
        Path path = Paths.get(filename);
        return Files.readAllBytes(path);        
    }
}
