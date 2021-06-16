package org.knou.crypt;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class Sha {
    MessageDigest md;
    public Sha(String method) throws NoSuchAlgorithmException {
        md = MessageDigest.getInstance(method);
    }

    public byte[] hash(byte[] data) {
        md.update(data);
        return md.digest();
    }
}
