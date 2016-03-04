package com.spectocor.micor.core.encryption;

import java.io.IOException;
import java.security.GeneralSecurityException;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

public class Aes128Cbc extends Encryptor<Encryptor.CipherTextIv> {

    public Aes128Cbc() {
        super("AES", 128, "AES/CBC/PKCS5Padding", "PBKDF2WithHmacSHA1");
    }

    @Override
    public byte[] encrypt(byte[] plaintext)
            throws GeneralSecurityException, IOException {
        byte[] iv = generateIv();
        Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM);
        SecretKey key = retrieveKeyFromKeystore();
        cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(iv));
        iv = cipher.getIV();
        byte[] byteCipherText = cipher.doFinal(plaintext);
        CipherTextIv textIv = new CipherTextIv(byteCipherText, iv);

        return objectToBytes(textIv);
    }

    @Override
    public byte[] decrypt(byte[] content)
            throws GeneralSecurityException, IOException, ClassNotFoundException {

        Cipher aesCipherForDecryption = Cipher.getInstance(CIPHER_ALGORITHM);
        SecretKey key = retrieveKeyFromKeystore();

        Object obj = bytesToObject(content);
        if (obj instanceof CipherTextIv) {
            CipherTextIv civ = (CipherTextIv) obj;
            aesCipherForDecryption.init(Cipher.DECRYPT_MODE, key,
                    new IvParameterSpec(civ.getIv()));
            return aesCipherForDecryption.doFinal(civ.getCipherText());
        }
        return null;
    }
}
