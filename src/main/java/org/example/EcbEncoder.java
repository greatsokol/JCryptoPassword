package org.example;

public class EcbEncoder extends CbcEcbEncoder {
    private static final String TRANSFORMATION = "AES/ECB/PKCS5Padding";
    private static final int SALT_SIZE = 32;

    private EcbEncoder() {
    }

    public static String Encode(String passwordKey, String plainText) {
        return Encode(passwordKey, plainText, TRANSFORMATION, false, SALT_SIZE);
    }

    public static String Decode(String passwordKey, String fullCipherDataString) {
        return Decode(passwordKey, fullCipherDataString, TRANSFORMATION, false, SALT_SIZE);
    }
}
