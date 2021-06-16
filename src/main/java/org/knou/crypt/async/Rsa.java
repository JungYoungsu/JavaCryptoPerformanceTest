package org.knou.crypt.async;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.security.*;

public class Rsa {
    PrivateKey pri;
    PublicKey pub;
    public void generateKey(int length) throws NoSuchAlgorithmException {
        KeyPairGenerator kg = KeyPairGenerator.getInstance("RSA");
        kg.initialize(length, new SecureRandom());
        KeyPair kp = kg.genKeyPair();
        pri = kp.getPrivate();
        pub = kp.getPublic();
    }

    public byte[] signPri(byte[] data, String method) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        Signature sign = Signature.getInstance(method);
        sign.initSign(pri);
        sign.update(data);
        return sign.sign();
    }

    public boolean verifyPub(byte[] data, byte[] signed, String method) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        Signature sign = Signature.getInstance(method);
        sign.initVerify(pub);
        sign.update(data);
        return sign.verify(signed);
    }

    public byte[] encrypt(byte[] dec) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, pub);
        return cipher.doFinal(dec);
    }

    public byte[] decrypt(byte[] enc) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, pri);
        return cipher.doFinal(enc);
    }
}
