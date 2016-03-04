package com.spectocor.micor.core.encryption;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.spec.KeySpec;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

public class Des extends Encryptor<byte[]> {

    public Des() {
        super("DES", 56, "PBEWithMD5AndDES", "PBEWithMD5AndDES");
    }

    @Override
    public byte[] decrypt(byte[] data) throws GeneralSecurityException, IOException {
        Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM);
        SecretKey key = retrieveKeyFromKeystore();
        cipher.init(Cipher.DECRYPT_MODE, key);
        return cipher.doFinal(data);
    }

    @Override
    public byte[] encrypt(byte[] data) throws GeneralSecurityException, IOException {
        Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM);
        SecretKey key = retrieveKeyFromKeystore();
        cipher.init(Cipher.ENCRYPT_MODE, key);
        return cipher.doFinal(data);
    }

    @Override
    public void generateKeyFromPassword(String password, byte[] salt) throws GeneralSecurityException, IOException {
        if (retrieveKeyFromKeystore() == null) {
            // get enough random bytes for the key
            KeySpec keySpec = new PBEKeySpec(password.toCharArray(), salt,
                    PBE_ITERATION_COUNT);
            SecretKeyFactory keyFactory = SecretKeyFactory
                    .getInstance(PBE_ALGORITHM);
            SecretKey key = keyFactory.generateSecret(keySpec);
            storeKeyToKeystore(key);
        }
    }
}