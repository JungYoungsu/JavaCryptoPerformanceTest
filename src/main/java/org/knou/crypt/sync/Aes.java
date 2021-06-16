package org.knou.crypt.sync;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

public class Aes {
    IvParameterSpec IV = new IvParameterSpec( new byte[]
                    { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
                      0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00});
    SecretKey key;
    String method;
    public Aes(String method) {
        this.method = method;
    }
    public void generateKey(int length) throws NoSuchAlgorithmException {
        KeyGenerator kg = KeyGenerator.getInstance("AES");
        kg.init(length);
        key = kg.generateKey();
    }

    public byte[] encrypt(byte[] plain) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        Cipher cipher = Cipher.getInstance(method);
        if(method.equals("AES")) cipher.init(Cipher.ENCRYPT_MODE, key);
        else cipher.init(Cipher.ENCRYPT_MODE, key, IV);

        return cipher.doFinal(plain);
    }

    public byte[] decrypt(byte[] enc) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        Cipher cipher = Cipher.getInstance(method);
        if(method.equals("AES")) cipher.init(Cipher.ENCRYPT_MODE, key);
        else cipher.init(Cipher.DECRYPT_MODE, key, IV);

        return cipher.doFinal(enc);
    }

    public byte[] getKey() {
        return key.getEncoded();
    }
}
