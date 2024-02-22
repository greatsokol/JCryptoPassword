package org.example;

import javax.crypto.Cipher;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.spec.KeySpec;

public abstract class CbcEcbBaseEncoder {
    private static final String SKF_ALGORITHM = "PBKDF2WithHmacSHA1";
    private static final String SK_ALGORITHM = "AES";
    private static final int KEY_LENGTH = 256;
    private static final int ITERATION_COUNT = 1000000;

    protected CbcEcbBaseEncoder() {
    }

    protected static CipherData Encode(String passwordKey,
                                       String transformationAlg,
                                       CipherData cipherData) {
        try {

            KeySpec spec = new PBEKeySpec(passwordKey.toCharArray(), cipherData.salt, ITERATION_COUNT, KEY_LENGTH); // AES-256
            Cipher cipher = Cipher.getInstance(transformationAlg);
            if (cipherData.ivBytes != null) {
                cipher.init(Cipher.ENCRYPT_MODE,
                        new SecretKeySpec(SecretKeyFactory.getInstance(SKF_ALGORITHM).generateSecret(spec).getEncoded(), SK_ALGORITHM),
                        new IvParameterSpec(cipherData.ivBytes));
            } else {
                cipher.init(Cipher.ENCRYPT_MODE,
                        new SecretKeySpec(SecretKeyFactory.getInstance(SKF_ALGORITHM).generateSecret(spec).getEncoded(), SK_ALGORITHM));
            }
            byte[] cipherText = cipher.doFinal(cipherData.cipherText);

            return new CipherData(cipherText, cipherData.ivBytes, cipherData.salt);
        } catch (Exception ex) {
            ex.printStackTrace();
            return null;
        }
    }

    protected static byte[] Decode(String passwordKey,
                                   String transformationAlg,
                                   CipherData cipherData) {
        try {
            KeySpec spec = new PBEKeySpec(passwordKey.toCharArray(), cipherData.salt, ITERATION_COUNT, KEY_LENGTH); // AES-256
            SecretKeyFactory f = SecretKeyFactory.getInstance(SKF_ALGORITHM);
            byte[] key = f.generateSecret(spec).getEncoded();
            SecretKeySpec keySpec = new SecretKeySpec(key, SK_ALGORITHM);
            Cipher cipher = Cipher.getInstance(transformationAlg);
            if (cipherData.ivBytes != null) {
                cipher.init(Cipher.DECRYPT_MODE, keySpec, new IvParameterSpec(cipherData.ivBytes));
            } else {
                cipher.init(Cipher.DECRYPT_MODE, keySpec);
            }
            return cipher.doFinal(cipherData.cipherText);
        } catch (Exception ex) {
            ex.printStackTrace();
            return null;
        }
    }

    protected static class CipherData {
        public byte[] cipherText;
        public byte[] ivBytes;
        public byte[] salt;

        public CipherData(byte[] cipherText, byte[] ivBytes, byte[] salt) {
            this.cipherText = cipherText;
            this.ivBytes = ivBytes;
            this.salt = salt;
        }
    }
}
