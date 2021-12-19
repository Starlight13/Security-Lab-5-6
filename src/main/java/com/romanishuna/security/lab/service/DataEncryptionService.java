package com.romanishuna.security.lab.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import java.security.SecureRandom;
import java.util.Base64;

@Service
public class DataEncryptionService {
    private final AesGcmService aesGcmService;
    private final AwsService awsService;
    public DataEncryptionService(@Autowired AesGcmService aesGcmService, @Autowired AwsService awsService) {
        this.aesGcmService = aesGcmService;
        this.awsService = awsService;
    }

    public EncryptionResult encrypt(String input, String password) {
        var salt = new byte[128];
        var b64Encoder = Base64.getEncoder();
        new SecureRandom().nextBytes(salt);

        try {
            GCMParameterSpec iv = aesGcmService.generateIv(16);
            SecretKey key = aesGcmService.getKeyFromPassword(password, salt);
            String cipheredTextB64 = b64Encoder.encodeToString(aesGcmService.encrypt(input, key, iv));
            return new EncryptionResult(cipheredTextB64 + "::" + b64Encoder.encodeToString(iv.getIV()), b64Encoder.encodeToString(awsService.encrypt(key.getEncoded())));
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    public String decrypt(String cipherText, String dek) {
        Base64.Decoder b64Decoder = Base64.getDecoder();
        String[] cipherTextSplit = cipherText.split("::");
        var iv = b64Decoder.decode(cipherTextSplit[1]);
        var key = awsService.decrypt(b64Decoder.decode(dek));
        var cipheredPhone = b64Decoder.decode(cipherTextSplit[0]);
        try {
            return aesGcmService.decrypt(cipheredPhone, aesGcmService.generateKey(key), aesGcmService.generateIv(iv));
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    public static class EncryptionResult {
        public String cipheredText;
        public String key;
        public EncryptionResult (String cipheredText, String key) {
            this.cipheredText = cipheredText;
            this.key = key;
        }
    }
}
