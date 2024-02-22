package org.example;

public class CbcEncoder extends CbcEcbEncoder {
    private static final String TRANSFORMATION = "AES/CBC/PKCS5Padding";
    private static final int SALT_SIZE = 32;

    private CbcEncoder() {
    }

    public static String Encode(String passwordKey, String plainText) {
        return Encode(passwordKey, plainText, TRANSFORMATION, true, SALT_SIZE);
    }

    public static String Decode(String passwordKey, String cipherText) {
        return Decode(passwordKey, cipherText, TRANSFORMATION, true, SALT_SIZE);
    }
}
