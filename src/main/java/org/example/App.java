package org.example;

import java.io.File;
import java.io.IOException;
import java.nio.file.Path;
import java.nio.file.Paths;

public class App
{
    public static void main( String[] args ) throws IOException {
        Path path = null;
        try {
            path = Paths.get(new File(".").getCanonicalPath(), ".keystore");
        } catch (IOException ex) {
            System.out.println(ex.getMessage());
        }

        ///***
        // Created keystore file with command:
        // keytool -importpass /path/to/.keystore -storetype PKCS12 -storepass 123456 -alias databasekey
        ///***
        if (path != null) {
            String keyStoreAndItemPassword = "123456";
            String storedPassword = PasswordLoader.getPassword(
                    path.toString(),
                    "PKCS12", keyStoreAndItemPassword,
                    "databasekey", keyStoreAndItemPassword
            );
            System.out.println(storedPassword);
        }
    }
}
