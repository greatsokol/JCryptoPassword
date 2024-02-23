package org.example;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

public abstract class CbcEcbBaseEncoder {
    private static final String SKF_ALGORITHM = "PBKDF2WithHmacSHA256";
    private static final String SK_ALGORITHM = "AES";
    private static final int KEY_LENGTH = 256;
    private static final int ITERATION_COUNT = 1000000;

    protected CbcEcbBaseEncoder() {
    }

    protected static CipherData EncodeDecode(int mode,
                                             String passwordKey,
                                             String transformationAlg,
                                             CipherData cipherData) {
        try {
            PBEKeySpec spec = new PBEKeySpec(passwordKey.toCharArray(), cipherData.salt, ITERATION_COUNT, KEY_LENGTH); // AES-256
            SecretKey secretKey = SecretKeyFactory.getInstance(SKF_ALGORITHM).generateSecret(spec);
            SecretKeySpec sk = new SecretKeySpec(secretKey.getEncoded(), SK_ALGORITHM);
            Cipher cipher = Cipher.getInstance(transformationAlg);
            if (cipherData.ivBytes != null) {
                cipher.init(mode, sk, new IvParameterSpec(cipherData.ivBytes));
            } else {
                cipher.init(mode, sk);
            }
            return new CipherData(cipher.doFinal(cipherData.cipherText), cipherData.ivBytes, cipherData.salt);
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
