package org.example;

import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyStore;

public class PasswordLoader {
    private PasswordLoader() {

    }

    public static String getPassword(String keyStorePath,
                              String keyStoreType,
                              String keyStorePassword,
                              String passwordAlias,
                              String passwordPassword
                              ) {
        try{
            InputStream keyStoreData = Files.newInputStream(Paths.get(keyStorePath));
            KeyStore keyStore = KeyStore.getInstance(keyStoreType);
            keyStore.load(keyStoreData, keyStorePassword.toCharArray());

//            Enumeration<String> aliases = keyStore.aliases();
//            while (aliases.hasMoreElements()) {
//                System.out.println(aliases.nextElement());
//            }

            KeyStore.ProtectionParameter entryPassword = new KeyStore.PasswordProtection(passwordPassword.toCharArray());
            KeyStore.SecretKeyEntry secretKeyEntry = (KeyStore.SecretKeyEntry) keyStore.getEntry(passwordAlias, entryPassword); //"mykey"

            SecretKey secretKey = secretKeyEntry.getSecretKey();
            SecretKeyFactory factory = SecretKeyFactory.getInstance(secretKey.getAlgorithm());
            PBEKeySpec keySpec = (PBEKeySpec) factory.getKeySpec(secretKey, PBEKeySpec.class);

            return new String(keySpec.getPassword());
        } catch (Exception ex) {
            System.out.println(ex.getMessage());
            return null;
        }
    }
}