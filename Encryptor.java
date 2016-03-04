package com.spectocor.micor.core.encryption;

import android.os.Environment;
import android.util.Base64;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.Serializable;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.KeySpec;
import java.util.Arrays;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

public abstract class Encryptor<T> {

    protected String CIPHER;
    protected int KEY_LENGTH_BITS;
    protected String CIPHER_ALGORITHM;
    protected int PBE_SALT_LENGTH_BITS;
    protected final String PBE_ALGORITHM;
    protected File KEYSTORE_FILE;

    // constants
    protected final int PBE_ITERATION_COUNT = 10000;
    protected final String RANDOM_ALGORITHM = "SHA1PRNG";
    protected final int IV_LENGTH_BYTES = 16;
    protected final String KEYSTORE_TYPE = "BKS";

    protected final String KEYSTORE_PATH = Environment.getExternalStorageDirectory().getPath() + "/13579/";
    protected final String KEYSTORE_PASSWORD = "password";
    protected final String KEY_PASSWORD = "toKey";
    protected final String SECRET_KEY_ALIAS = "secretKeyAlias"; // TODO: this can be the changeable key ID
    protected final String KEYSTORE_NAME = "testKeyStore.keystore";

    public Encryptor(String cif, int len, String algo, String pbeAlgo) {
        this.CIPHER = cif;
        this.KEY_LENGTH_BITS = len;
        this.CIPHER_ALGORITHM = algo;
        this.PBE_SALT_LENGTH_BITS = len;
        this.PBE_ALGORITHM = pbeAlgo;
    }

    /**
     * @param plaintext Byte[] to be encrypted
     * @return Encrypted data in format byte[]
     * @throws GeneralSecurityException
     * @throws IOException
     */
    public abstract byte[] encrypt(byte[] plaintext) throws GeneralSecurityException, IOException;

    /**
     * @param content Data to be decrypted in format byte[] (DES) or CipherTextIv (AES)
     * @return Decrypted byte[]
     * @throws GeneralSecurityException
     * @throws IOException
     */
    public abstract byte[] decrypt(byte[] content) throws GeneralSecurityException, IOException, ClassNotFoundException;

    /**
     * @return The initialization vector for AES
     * @throws NoSuchAlgorithmException
     */
    public byte[] generateIv() throws NoSuchAlgorithmException {
        SecureRandom random = SecureRandom.getInstance(RANDOM_ALGORITHM);
        byte[] b = new byte[IV_LENGTH_BYTES];
        random.nextBytes(b);
        return b;
    }

    /**
     * For AES only. Holder class that allows us to bundle CipherText and IV together.
     */
    public static class CipherTextIv implements Serializable {
        private final byte[] cipherText;
        private final byte[] iv;

        public byte[] getCipherText() {
            return cipherText;
        }

        public byte[] getIv() {
            return iv;
        }

        /**
         * Construct a new bundle of CipherText and IV.
         *
         * @param c The CipherText
         * @param i The IV
         */
        public CipherTextIv(byte[] c, byte[] i) {
            cipherText = new byte[c.length];
            System.arraycopy(c, 0, cipherText, 0, c.length);
            iv = new byte[i.length];
            System.arraycopy(i, 0, iv, 0, i.length);
        }

        @Override
        public String toString() {
            String ivString = Base64.encodeToString(iv, Base64.NO_WRAP);
            String cipherTextString = Base64.encodeToString(cipherText, Base64.NO_WRAP);
            return String.format(ivString + ":" + cipherTextString);
        }

        @Override
        public int hashCode() {
            final int prime = 31;
            int result = 1;
            result = prime * result + Arrays.hashCode(cipherText);
            result = prime * result + Arrays.hashCode(iv);
            return result;
        }

        @Override
        public boolean equals(Object obj) {
            if (this == obj)
                return true;
            if (obj == null)
                return false;
            if (getClass() != obj.getClass())
                return false;
            CipherTextIv other = (CipherTextIv) obj;
            if (!Arrays.equals(cipherText, other.cipherText))
                return false;
            if (!Arrays.equals(iv, other.iv))
                return false;
            return true;
        }
    }

    /**
     * Generate a random key and store it in KeyStore
     *
     * @return A random key
     * @throws GeneralSecurityException if encryption algorithm is not implemented on this system
     * @throws IOException
     */
    public void generateKey() throws IOException, GeneralSecurityException {
        if (retrieveKeyFromKeystore() == null) {
            KeyGenerator keyGen = KeyGenerator.getInstance(CIPHER);
            keyGen.init(KEY_LENGTH_BITS);
            SecretKey key = keyGen.generateKey();
            storeKeyToKeystore(key);
        }
    }

    /**
     * Generate a password-based random key and store it in KeyStore
     *
     * @param password The password to derive the keys from
     * @return A random key based on password
     * @throws GeneralSecurityException if encryption algorithm is not implemented on this system
     *                                  or keyFactory is invalid
     */
    public void generateKeyFromPassword(String password, byte[] salt) throws GeneralSecurityException, IOException {
        if (retrieveKeyFromKeystore() == null) {
            KeySpec keySpec = new PBEKeySpec(password.toCharArray(), salt,
                    PBE_ITERATION_COUNT, KEY_LENGTH_BITS);
            SecretKeyFactory keyFactory = SecretKeyFactory
                    .getInstance(PBE_ALGORITHM);
            byte[] keyBytes = keyFactory.generateSecret(keySpec).getEncoded();

            byte[] subsetKeyBytes = copyOfRange(keyBytes, 0, KEY_LENGTH_BITS / 8);

            SecretKey key = new SecretKeySpec(subsetKeyBytes, CIPHER);
            storeKeyToKeystore(key);
        }
    }

    /**
     * @return The random salt suitable for generateKeyFromPassword.
     */
    public byte[] generateSalt() throws GeneralSecurityException {
        SecureRandom random = SecureRandom.getInstance(RANDOM_ALGORITHM);
        byte[] b = new byte[PBE_SALT_LENGTH_BITS];
        random.nextBytes(b);
        return b;
    }

    /**
     * Copy the elements from the start to the end
     *
     * @param from  the source
     * @param start the start index to copy
     * @param end   the end index to finish
     * @return the new buffer
     */
    private byte[] copyOfRange(byte[] from, int start, int end) {
        int length = end - start;
        byte[] result = new byte[length];
        System.arraycopy(from, start, result, 0, length);
        return result;
    }

    /**
     * @param obj
     * @return byte array of obj
     * @throws IOException
     */
    public byte[] objectToBytes(Object obj) throws IOException {
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        ObjectOutputStream out = new ObjectOutputStream(bOut);
        out.writeObject(obj);
        byte[] objBytes = bOut.toByteArray();
        bOut.close();
        out.close();
        return objBytes;
    }

    /**
     * @param bytes
     * @return original obj
     * @throws IOException
     * @throws ClassNotFoundException
     */
    public Object bytesToObject(byte[] bytes) throws IOException, ClassNotFoundException {
        ByteArrayInputStream bIn = new ByteArrayInputStream(bytes);
        ObjectInputStream oIn = new ObjectInputStream(bIn);
        Object obj = oIn.readObject();
        bIn.close();
        oIn.close();

        return obj;
    }

    /**
     * @param secretKey The SecretKey to be stored
     * @throws IOException
     * @throws GeneralSecurityException
     */
    protected void storeKeyToKeystore(SecretKey secretKey) throws IOException, GeneralSecurityException {

        KeyStore keyStore = createOrLoadKeystore();
        FileOutputStream fOut = new FileOutputStream(KEYSTORE_FILE);
        KeyStore.SecretKeyEntry secretKeyEntry = new KeyStore.SecretKeyEntry(secretKey);
        KeyStore.PasswordProtection keyPassword = new KeyStore.PasswordProtection(KEY_PASSWORD.toCharArray());
        keyStore.setEntry(SECRET_KEY_ALIAS, secretKeyEntry, keyPassword);
        keyStore.store(fOut, KEYSTORE_PASSWORD.toCharArray());
        fOut.close();
    }

    /**
     * @return The SecretKey returned from KeyStore
     * @throws GeneralSecurityException
     * @throws IOException
     */
    protected SecretKey retrieveKeyFromKeystore() throws GeneralSecurityException, IOException {

        KeyStore keyStore = createOrLoadKeystore();
        KeyStore.PasswordProtection keyPassword = new KeyStore.PasswordProtection(KEY_PASSWORD.toCharArray());
        try {
            KeyStore.SecretKeyEntry keyEntry = (KeyStore.SecretKeyEntry) keyStore.getEntry(SECRET_KEY_ALIAS, keyPassword);
            SecretKey key = keyEntry.getSecretKey();
            return key;
        } catch (Exception e) {
            return null;
        }

    }

    /**
     * Create a KeyStore and load it if it's created already.
     *
     * @return The KeyStore
     * @throws GeneralSecurityException
     * @throws IOException
     */
    protected KeyStore createOrLoadKeystore() throws GeneralSecurityException, IOException {
        File myDir = new File(KEYSTORE_PATH);
        myDir.mkdirs();
        KEYSTORE_FILE = new File(myDir, KEYSTORE_NAME);

        final KeyStore keyStore = KeyStore.getInstance(KEYSTORE_TYPE);
        if (KEYSTORE_FILE.exists()) {
            FileInputStream fIn = new FileInputStream(KEYSTORE_FILE);
            keyStore.load(fIn, KEYSTORE_PASSWORD.toCharArray());
            fIn.close();
        } else {
            keyStore.load(null, null);
            FileOutputStream fOut = new FileOutputStream(KEYSTORE_FILE);
            keyStore.store(fOut, KEYSTORE_PASSWORD.toCharArray());
            fOut.close();
        }

        return keyStore;
    }
}
