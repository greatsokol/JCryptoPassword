package org.example;

import javax.crypto.Cipher;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.security.spec.KeySpec;
import java.util.Base64;

public abstract class CbcEcbEncoder {
    private static final String SKF_ALGORITHM = "PBKDF2WithHmacSHA1";
    private static final String SK_ALGORITHM = "AES";
    private static final int IVBYTES_SIZE = 16;

    protected CbcEcbEncoder() {
    }

    protected static String Encode(String passwordKey, String plainText, String transformationAlg, boolean withIV, int saltSize) {
        try {
            SecureRandom random = new SecureRandom();
            byte[] salt = new byte[saltSize];
            byte[] ivBytes = new byte[IVBYTES_SIZE];
            random.nextBytes(salt);

            KeySpec spec = new PBEKeySpec(passwordKey.toCharArray(), salt, 1000000, 256); // AES-256
            Cipher cipher = Cipher.getInstance(transformationAlg);
            if (withIV) {
                random.nextBytes(ivBytes);
                cipher.init(Cipher.ENCRYPT_MODE,
                        new SecretKeySpec(SecretKeyFactory.getInstance(SKF_ALGORITHM).generateSecret(spec).getEncoded(), SK_ALGORITHM),
                        new IvParameterSpec(ivBytes));
            } else {
                cipher.init(Cipher.ENCRYPT_MODE,
                        new SecretKeySpec(SecretKeyFactory.getInstance(SKF_ALGORITHM).generateSecret(spec).getEncoded(), SK_ALGORITHM));
            }
            byte[] cipherText = cipher.doFinal(plainText.getBytes(StandardCharsets.UTF_8));

            byte[] fullCipherData;
            if (withIV) {
                fullCipherData = new byte[cipherText.length + IVBYTES_SIZE + saltSize];
                System.arraycopy(ivBytes, 0, fullCipherData, 0, IVBYTES_SIZE);
                System.arraycopy(salt, 0, fullCipherData, IVBYTES_SIZE, saltSize);
                System.arraycopy(cipherText, 0, fullCipherData, IVBYTES_SIZE + saltSize, cipherText.length);
            } else {
                fullCipherData = new byte[cipherText.length + saltSize];
                System.arraycopy(salt, 0, fullCipherData, 0, saltSize);
                System.arraycopy(cipherText, 0, fullCipherData, saltSize, cipherText.length);
            }

            return Base64.getEncoder().encodeToString(fullCipherData);
        } catch (Exception ex) {
            ex.printStackTrace();
            return null;
        }
    }

    protected static String Decode(String passwordKey, String fullCipherDataString, String transformationAlg, boolean withIV, int saltSize) {
        try {
            byte[] fullCipherData = Base64.getDecoder().decode(fullCipherDataString);
            byte[] salt = new byte[saltSize];
            byte[] ivBytes = new byte[IVBYTES_SIZE];
            byte[] cipherText;
            if (withIV) {
                cipherText = new byte[fullCipherData.length - (IVBYTES_SIZE + saltSize)];
                System.arraycopy(fullCipherData, 0, ivBytes, 0, IVBYTES_SIZE);
                System.arraycopy(fullCipherData, IVBYTES_SIZE, salt, 0, saltSize);
                System.arraycopy(fullCipherData, IVBYTES_SIZE + saltSize, cipherText, 0, fullCipherData.length - (IVBYTES_SIZE + saltSize));
            } else {
                cipherText = new byte[fullCipherData.length - saltSize];
                System.arraycopy(fullCipherData, 0, salt, 0, saltSize);
                System.arraycopy(fullCipherData, saltSize, cipherText, 0, fullCipherData.length - saltSize);
            }

            KeySpec spec = new PBEKeySpec(passwordKey.toCharArray(), salt, 1000000, 256); // AES-256
            SecretKeyFactory f = SecretKeyFactory.getInstance(SKF_ALGORITHM);
            byte[] key = f.generateSecret(spec).getEncoded();
            SecretKeySpec keySpec = new SecretKeySpec(key, SK_ALGORITHM);
            Cipher cipher = Cipher.getInstance(transformationAlg);
            if (withIV) {
                cipher.init(Cipher.DECRYPT_MODE, keySpec, new IvParameterSpec(ivBytes));
            } else {
                cipher.init(Cipher.DECRYPT_MODE, keySpec);
            }
            return new String(cipher.doFinal(cipherText), StandardCharsets.UTF_8);
        } catch (Exception ex) {
            ex.printStackTrace();
            return null;
        }
    }
}
