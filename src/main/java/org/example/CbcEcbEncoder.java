package org.example;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Base64;

public class CbcEcbEncoder extends CbcEcbBaseEncoder {
    private static final int IVBYTES_SIZE = 16;

    protected CbcEcbEncoder() {
    }

    protected static String Encode(String passwordKey,
                                   String plainText,
                                   String transformationAlg,
                                   boolean withIV,
                                   int saltSize) {
        int ivSize = withIV ? IVBYTES_SIZE : 0;
        SecureRandom random = new SecureRandom();
        byte[] salt = new byte[saltSize];
        byte[] ivBytes = withIV ? new byte[IVBYTES_SIZE] : null;
        random.nextBytes(salt);
        CipherData cipherData = Encode(
                passwordKey,
                transformationAlg,
                new CipherData(plainText.getBytes(StandardCharsets.UTF_8), ivBytes, salt)
        );
        if (cipherData == null) return null;

        byte[] cipherTextWithSaltAndVector = new byte[cipherData.cipherText.length + ivSize + saltSize];
        if (withIV) System.arraycopy(ivBytes, 0, cipherTextWithSaltAndVector, 0, IVBYTES_SIZE);
        System.arraycopy(salt, 0, cipherTextWithSaltAndVector, ivSize, saltSize);
        System.arraycopy(cipherData.cipherText, 0, cipherTextWithSaltAndVector, ivSize + saltSize, cipherData.cipherText.length);

        return Base64.getEncoder().encodeToString(cipherTextWithSaltAndVector);
    }

    protected static String Decode(String passwordKey,
                                   String cipherTextWithSaltAndVector,
                                   String transformationAlg,
                                   boolean withIV,
                                   int saltSize) {
        int ivSize = withIV ? IVBYTES_SIZE : 0;
        byte[] fullCipherData = Base64.getDecoder().decode(cipherTextWithSaltAndVector);
        byte[] salt = new byte[saltSize];
        byte[] ivBytes = new byte[IVBYTES_SIZE];
        byte[] cipherText = new byte[fullCipherData.length - (ivSize + saltSize)];
        if (withIV) System.arraycopy(fullCipherData, 0, ivBytes, 0, IVBYTES_SIZE);
        System.arraycopy(fullCipherData, ivSize, salt, 0, saltSize);
        System.arraycopy(fullCipherData, ivSize + saltSize, cipherText, 0, fullCipherData.length - (ivSize + saltSize));

        byte[] plainBytes = Decode(passwordKey, transformationAlg, new CipherData(cipherText, withIV ? ivBytes : null, salt));
        if (plainBytes == null) return null;
        return new String(plainBytes, StandardCharsets.UTF_8);
    }
}
