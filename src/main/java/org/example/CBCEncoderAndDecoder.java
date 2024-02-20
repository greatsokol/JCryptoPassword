package org.example;

import javax.crypto.Cipher;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.SecureRandom;
import java.security.spec.KeySpec;

/**
 * CBC (Cipher Block Chaining)
 */
public class CBCEncoderAndDecoder {
    public static class EncodedData {
        public EncodedData(byte[] ivBytes, byte[] salt, byte[] cipherText) {
            this.ivBytes = new byte[ivBytes.length];
            System.arraycopy(ivBytes, 0, this.ivBytes, 0, ivBytes.length);

            this.salt = new byte[salt.length];
            System.arraycopy(salt, 0, this.salt, 0, salt.length);

            this.cipherText = new byte[cipherText.length];
            System.arraycopy(cipherText, 0, this.cipherText, 0, cipherText.length);
        }
        public byte[] ivBytes;
        public byte[] salt;
        public byte[] cipherText;
    }


    private static final String TRANSFORMATION = "AES/CBC/PKCS5Padding";
    private static final String SKF_ALGORITHM = "PBKDF2WithHmacSHA1";
    private static final String SK_ALGORITHM = "AES";

    private CBCEncoderAndDecoder(){}

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

    public static EncodedData Encode(String pathToKeyFile, int mode, byte[] plainText){
        String passwordKey = loadKeyFromFile(pathToKeyFile);
        if (passwordKey == null) return null;

        try{
            SecureRandom random = new SecureRandom();
            byte[] salt = new byte[16];
            random.nextBytes(salt);

            KeySpec spec = new PBEKeySpec(passwordKey.toCharArray(), salt, 1000000, 256); // AES-256
            SecretKeyFactory f = SecretKeyFactory.getInstance(SKF_ALGORITHM);

            byte[] key = f.generateSecret(spec).getEncoded();
            SecretKeySpec keySpec = new SecretKeySpec(key, SK_ALGORITHM);

            byte[] ivBytes = new byte[16];
            random.nextBytes(ivBytes);
            IvParameterSpec iv = new IvParameterSpec(ivBytes);

            Cipher cipher = Cipher.getInstance(TRANSFORMATION);
            cipher.init(mode, keySpec, iv);
            byte[] cipherText = cipher.doFinal(plainText);

            return new EncodedData(ivBytes, salt, cipherText);
        } catch (Exception ex) {
            System.out.println(ex.getClass()+" "+ex.getMessage());
            return null;
        }
    }

    public static String Decode(String pathToKeyFile, int mode, EncodedData encodedData){
        String passwordKey = loadKeyFromFile(pathToKeyFile);
        if (passwordKey == null) return null;

        try{
            KeySpec spec = new PBEKeySpec(passwordKey.toCharArray(), encodedData.salt, 1000000, 256); // AES-256
            SecretKeyFactory f = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
            byte[] key = f.generateSecret(spec).getEncoded();
            SecretKeySpec keySpec = new SecretKeySpec(key, "AES");
            IvParameterSpec iv = new IvParameterSpec(encodedData.ivBytes);
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(mode, keySpec, iv);
            byte[] plainText = cipher.doFinal(encodedData.cipherText);
            return new String(plainText, StandardCharsets.UTF_8);
        } catch (Exception ex) {
            System.out.println(ex.getClass()+" "+ex.getMessage()+'\n'+ex.fillInStackTrace());
            return null;
        }
    }
}
