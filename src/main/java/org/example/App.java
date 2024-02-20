package org.example;

import javax.crypto.Cipher;
import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.nio.file.Paths;

public class App
{
    private static String getPathToFileInApplicationDir(String fileName) {
        Path path = null;
        try {
            path = Paths.get(new File(".").getCanonicalPath(), fileName);
        } catch (IOException ex) {
            System.out.println(ex.getMessage());
        }
        return path == null ? null : path.toString();
    }

    private static void LoadPasswordFromKeystoreFile(){
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
            System.out.println(storedPassword);
        }
    }


    private static void CBCEncodeAndDecode(){
        String pathToKeyFile = getPathToFileInApplicationDir(".pass");
        String plainText = "password11";
        CBCEncoderAndDecoder.EncodedData encodedData = CBCEncoderAndDecoder.Encode(pathToKeyFile, Cipher.ENCRYPT_MODE, plainText.getBytes(StandardCharsets.UTF_8));
        String decodedPlainText = CBCEncoderAndDecoder.Decode(pathToKeyFile, Cipher.DECRYPT_MODE, encodedData);
        System.out.println(decodedPlainText);
    }

    private static void ECBEncodeAndDecode(){
        String pathToKeyFile = getPathToFileInApplicationDir(".pass");
        String plainText = "password22";
        byte[] encoded = ECBEncoderAndDecoder.Encode(pathToKeyFile, plainText.getBytes(StandardCharsets.UTF_8));
        String decodedPlainText = ECBEncoderAndDecoder.Decode(pathToKeyFile, encoded);
        System.out.println(decodedPlainText);
    }


    public static void main( String[] args ){
        LoadPasswordFromKeystoreFile();
        CBCEncodeAndDecode();
        ECBEncodeAndDecode();
    }
}
