package org.knou.crypt.async;

import java.security.*;
import java.security.spec.ECGenParameterSpec;

public class Ecdsa {
    KeyPair kp;
    public void generateKey() throws NoSuchAlgorithmException, InvalidAlgorithmParameterException {
        KeyPairGenerator kg = KeyPairGenerator.getInstance("EC");

        kg.initialize(new ECGenParameterSpec("sect163k1"), new SecureRandom());
        kp = kg.generateKeyPair();
    }

    public byte[] signPri(byte[] data, String method) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        Signature sign = Signature.getInstance(method);
        sign.initSign(kp.getPrivate());

        sign.update(data);
        return sign.sign();
    }
    public boolean verifyPub(byte[] data, byte[] signed, String method) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        Signature sign = Signature.getInstance(method);
        sign.initVerify(kp.getPublic());

        sign.update(data);
        return sign.verify(signed);
    }
}
