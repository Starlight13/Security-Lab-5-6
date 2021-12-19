package com.romanishuna.security.lab.service;

import org.springframework.stereotype.Service;

import javax.crypto.*;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;

@Service
public class AesGcmService {
    private static final String ALGORITHM = "AES/GCM/NoPadding";
    private static final SecureRandom secureRandom = new SecureRandom();
    public static SecretKey generateKey(int n) throws NoSuchAlgorithmException {
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(n);
        return keyGenerator.generateKey();
    }

    public SecretKey generateKey(byte [] seed) {
        return new SecretKeySpec(seed, "AES");
    }

    public SecretKey getKeyFromPassword(String password, byte[] salt)
            throws NoSuchAlgorithmException, InvalidKeySpecException
    {
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        KeySpec spec = new PBEKeySpec(password.toCharArray(), salt, 65536, 256);
        return new SecretKeySpec(factory.generateSecret(spec).getEncoded(), "AES");
    }

    public GCMParameterSpec generateIv(int n) {
        byte[] iv = new byte[n];
        secureRandom.nextBytes(iv);
        return new GCMParameterSpec(128, iv);
    }

    public GCMParameterSpec generateIv(byte [] iv){
        return new GCMParameterSpec(128, iv);
    }

    public byte[] encrypt(String input, SecretKey key, GCMParameterSpec iv)
            throws NoSuchPaddingException, NoSuchAlgorithmException,
            InvalidAlgorithmParameterException, InvalidKeyException,
            BadPaddingException, IllegalBlockSizeException
    {
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, key, iv);
        return cipher.doFinal(input.getBytes());
    }

    public String decrypt(byte[] cipherText, SecretKey key, GCMParameterSpec iv)
            throws NoSuchPaddingException, NoSuchAlgorithmException,
            InvalidAlgorithmParameterException, InvalidKeyException,
            BadPaddingException, IllegalBlockSizeException
    {
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, key, iv);
        byte[] plainText = cipher.doFinal(cipherText);
        return new String(plainText);
    }
}
