package org.example;

import java.io.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

public class App {
    private static String getPathToFileInApplicationDir(String fileName) {
        Path path = null;
        try {
            path = Paths.get(new File(".").getCanonicalPath(), fileName);
        } catch (IOException ex) {
            System.out.println(ex.getMessage());
        }
        return path == null ? null : path.toString();
    }

    private static String loadKeyFromFile(String pathToKeyFile) {
        try {
            try (InputStream keyFileData = Files.newInputStream(Paths.get(pathToKeyFile))) {
                BufferedReader bufferedReader = new BufferedReader(new InputStreamReader(keyFileData));
                return bufferedReader.readLine();
            }
        } catch (IOException ex) {
            System.out.println("File not loaded " + ex.getMessage());
            return null;
        }
    }

    private static void LoadPasswordFromKeystoreFile() {
        String path = getPathToFileInApplicationDir(".keystore");

        ///***
        // Created keystore file with command:
        // keytool -importpass /path/to/.keystore -storetype PKCS12 -storepass 123456 -alias databasekey
        ///***
        if (path != null) {
            String keyStoreAndItemPassword = "123456";
            String storedPassword = PasswordLoader.getPassword(path, "PKCS12", keyStoreAndItemPassword,
                    "databasekey", keyStoreAndItemPassword
            );
            System.out.format("Loaded from keystore file (%s): %s\n", path, storedPassword);
        }
    }


    private static void CBCEncodeAndDecode() {
        String passwordKey = loadKeyFromFile(getPathToFileInApplicationDir(".pass"));
        if (passwordKey == null) return;

        String cipher = CbcEncoder.Encode(passwordKey, "password");
        String plainText = CbcEncoder.Decode(passwordKey, cipher);

        System.out.format("%s. Plain: %s, Cipher: %s\n", CbcEncoder.class, plainText, cipher);
    }

    private static void ECBEncodeAndDecode() {
        String passwordKey = loadKeyFromFile(getPathToFileInApplicationDir(".pass"));
        if (passwordKey == null) return;

        String cipher = EcbEncoder.Encode(passwordKey, "password");
        String plainText = EcbEncoder.Decode(passwordKey, cipher);

        System.out.format("%s. Plain: %s, Cipher: %s\n", EcbEncoder.class, plainText, cipher);
    }


    public static void main(String[] args) {
        LoadPasswordFromKeystoreFile();
        CBCEncodeAndDecode();
        ECBEncodeAndDecode();
    }
}
