package org.example;

import javax.crypto.Cipher;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

public class CbcSimpleEncoder extends CbcEcbBaseEncoder {
    private static final String TRANSFORMATION = "AES/CBC/PKCS5Padding";

    private CbcSimpleEncoder() {
    }

    /**
     * plain text can be encoded with command:
     * openssl enc -aes-256-cbc -k %key% -pbkdf2 -iter 1000000 -a -p -S %salt_hex% -iv %iv_hex% -md sha256 -in %path/to/plaintext%
     */
    public static String EncodeDecode(int mode, String key, String salt, String iv, String text) {
        if(salt.length() != 8) throw new IllegalArgumentException("Invalid salt length ("+salt.length()+"). Should be 8 symbols.");
        if(iv.length() != 16) throw new IllegalArgumentException("Invalid IV length ("+iv.length()+"). Should be 16 symbols.");

        byte[] saltBytes = salt.getBytes(StandardCharsets.UTF_8);
        byte[] ivBytes = iv.getBytes(StandardCharsets.UTF_8);

        //System.out.println("hex salt: " + new BigInteger(1, saltBytes).toString(16) );
        //System.out.println("hex iv: " + new BigInteger(1, ivBytes).toString(16) );

        byte[] textBytes;
        if (mode == Cipher.DECRYPT_MODE) {
            textBytes = Base64.getDecoder().decode(text);
        } else {
            textBytes = text.getBytes(StandardCharsets.UTF_8);
        }

        CipherData cipherData = EncodeDecode(mode, key, TRANSFORMATION, new CipherData(textBytes, ivBytes, saltBytes));
        if (cipherData == null) return null;
        if (mode == Cipher.DECRYPT_MODE) {
           return new String(cipherData.cipherText, StandardCharsets.UTF_8);
        } else {
            return Base64.getEncoder().encodeToString(cipherData.cipherText);
        }
    }
}
