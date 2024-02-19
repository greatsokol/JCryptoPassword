package org.example;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

public class PasswordLoader {
    private PasswordLoader() {

    }

    public static String getPassword(String keyStorePath,
                              String keyStoreType,
                              String keyStorePassword,
                              String passwordAlias,
                              String passwordPassword
                              ) {
        KeyStore keyStore;
        try {
            keyStore = KeyStore.getInstance(keyStoreType);
        } catch (KeyStoreException ex) {
           System.out.println("KeyStore instance not created" + ex.getMessage());
           return null;
        }

        try {
            try (InputStream keyStoreData = Files.newInputStream(Paths.get(keyStorePath))) {
                try {
                    keyStore.load(keyStoreData, keyStorePassword.toCharArray());
                } catch (Exception ex) {
                    System.out.println("Keystore not loaded "+ex.getMessage());
                    return null;
                }
            }
        } catch (IOException ex) {
            System.out.println("File not loaded "+ex.getMessage());
            return null;
        }

//        try {
//            Enumeration<String> aliases = keyStore.aliases();
//            while (aliases.hasMoreElements()) {
//                System.out.println(aliases.nextElement());
//            }
//        } catch (KeyStoreException ex) {
//            System.out.println(ex.getMessage());
//            return null;
//        }

        KeyStore.SecretKeyEntry secretKeyEntry;
        KeyStore.ProtectionParameter entryPassword = new KeyStore.PasswordProtection(passwordPassword.toCharArray());
        try {
            secretKeyEntry = (KeyStore.SecretKeyEntry) keyStore.getEntry(passwordAlias, entryPassword); //"mykey"
        } catch (Exception ex) {
            System.out.println(ex.getMessage());
            return null;
        }

        SecretKeyFactory factory;
        try {
            factory = SecretKeyFactory.getInstance(secretKeyEntry.getSecretKey().getAlgorithm());
        } catch (NoSuchAlgorithmException ex) {
            System.out.println(ex.getMessage());
            return null;
        }

        PBEKeySpec keySpec;
        try {
            keySpec = (PBEKeySpec) factory.getKeySpec(secretKeyEntry.getSecretKey(), PBEKeySpec.class);
        } catch(InvalidKeySpecException ex) {
            System.out.println(ex.getMessage());
            return null;
        }

        return new String(keySpec.getPassword());
    }
}