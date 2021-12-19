package com.romanishuna.security.lab.service;

import com.amazonaws.auth.AWSStaticCredentialsProvider;
import com.amazonaws.auth.BasicAWSCredentials;
import com.amazonaws.encryptionsdk.AwsCrypto;
import com.amazonaws.encryptionsdk.CommitmentPolicy;
import com.amazonaws.encryptionsdk.CryptoResult;
import com.amazonaws.encryptionsdk.kms.KmsMasterKey;
import com.amazonaws.encryptionsdk.kms.KmsMasterKeyProvider;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.util.Collections;
import java.util.Map;

@Service
public class AwsService {

    private final String KEY_ARN = "arn:aws:kms:us-east-2:125481175000:key/1ac8e609-7827-42ce-9077-bc15af8e7358";
    private final AwsCrypto crypto;
    private final KmsMasterKeyProvider keyProvider;

    public AwsService (@Value("${aws.key.arn}") String KEY_ARN,
                       @Value("${aws.access}") String AWS_ACCESS,
                       @Value("${aws.secret}") String AWS_SECRET) {
        var credentials = new BasicAWSCredentials(AWS_SECRET, AWS_ACCESS);
        crypto = AwsCrypto
                .builder()
                .withCommitmentPolicy(CommitmentPolicy.RequireEncryptRequireDecrypt)
                .build();
        keyProvider = KmsMasterKeyProvider
                .builder()
                .withCredentials(new AWSStaticCredentialsProvider(credentials))
                .buildStrict(KEY_ARN);
    }

    public byte[] encrypt(byte[] plainText) {
        final Map<String, String> encryptionContext = Collections.singletonMap("KeyAppContext", "KeyAppContextValue");
        final CryptoResult<byte[], KmsMasterKey> encryptResult = crypto.encryptData(keyProvider, plainText, encryptionContext);
        return encryptResult.getResult();
    }

    public byte[] decrypt(byte[] cipheredText) {
        final CryptoResult<byte[], KmsMasterKey> decryptResult = crypto.decryptData(keyProvider, cipheredText);
        return decryptResult.getResult();
    }
}
