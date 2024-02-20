package org.example;

import javax.crypto.Cipher;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.spec.KeySpec;

public class ECBEncoderAndDecoder {
    private static final String TRANSFORMATION = "AES/ECB/PKCS5Padding";
    private static final String SKF_ALGORITHM = "PBKDF2WithHmacSHA1";
    private static final String SK_ALGORITHM = "AES";
    private ECBEncoderAndDecoder(){}

    private static String loadKeyFromFile(String pathToKeyFile){
        try {
            try (InputStream keyFileData = Files.newInputStream(Paths.get(pathToKeyFile))) {
                BufferedReader bufferedReader = new BufferedReader(new InputStreamReader(keyFileData));
                return bufferedReader.readLine();
            }
        } catch (IOException ex) {
            System.out.println("File not loaded "+ex.getMessage());
            return null;
        }
    }

    private static byte[] EncodeOrDecode(String pathToKeyFile, int mode, byte[] plainText){
        String passwordKey = loadKeyFromFile(pathToKeyFile);
        if (passwordKey == null) return null;

        try {
            KeySpec spec = new PBEKeySpec(passwordKey.toCharArray(), "const_salt_here".getBytes(StandardCharsets.UTF_8), 1000000, 256); // AES-256
            byte[] key = SecretKeyFactory.getInstance(SKF_ALGORITHM).generateSecret(spec).getEncoded();
            SecretKeySpec keySpec = new SecretKeySpec(key, SK_ALGORITHM);

            Cipher cipher = Cipher.getInstance(TRANSFORMATION);
            cipher.init(mode, keySpec);

            return cipher.doFinal(plainText);
        } catch (Exception ex){
            System.out.println(ex.getClass()+" "+ex.getMessage());
            return null;
        }
    }

    public static byte[] Encode(String pathToKeyFile, byte[] plainText){
        return EncodeOrDecode(pathToKeyFile, Cipher.ENCRYPT_MODE, plainText);
    }

    public static String Decode(String pathToKeyFile, byte[] cipherText) {
        byte[] plainData = EncodeOrDecode(pathToKeyFile, Cipher.DECRYPT_MODE, cipherText);
        if(plainData == null) return null;
        return new String(plainData, StandardCharsets.UTF_8);
    }
}
