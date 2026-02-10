package io.dodn.springboot.core.domain.pki.crypto;

import io.dodn.springboot.core.domain.pki.vo.EncryptedPrivateKey;
import io.dodn.springboot.core.domain.pki.vo.KeyAlgorithm;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import javax.crypto.Cipher;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Arrays;

@Service
public class CaKeyService {

    private static final String AES_GCM = "AES/GCM/NoPadding";
    private static final int GCM_IV_LENGTH = 12;
    private static final int GCM_TAG_LENGTH = 128;
    private static final int SALT_LENGTH = 16;
    private static final int PBKDF2_ITERATIONS = 310_000;
    private static final int KEY_LENGTH = 256;

    private final String keyEncryptionSecret;
    private final SecureRandom secureRandom = new SecureRandom();

    public CaKeyService(@Value("${pki.key-encryption-secret}") String keyEncryptionSecret) {
        this.keyEncryptionSecret = keyEncryptionSecret;
    }

    public KeyPair generateKeyPair(KeyAlgorithm algorithm) {
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance(algorithm.getJcaAlgorithm(), "BC");
            if ("RSA".equals(algorithm.getJcaAlgorithm())) {
                generator.initialize(algorithm.getKeySize(), secureRandom);
            } else {
                ECGenParameterSpec ecSpec = new ECGenParameterSpec(algorithm.getCurveName());
                generator.initialize(ecSpec, secureRandom);
            }
            return generator.generateKeyPair();
        } catch (Exception e) {
            throw new IllegalStateException("Failed to generate key pair for algorithm: " + algorithm.type(), e);
        }
    }

    public EncryptedPrivateKey encrypt(PrivateKey privateKey, String alias) {
        try {
            byte[] salt = new byte[SALT_LENGTH];
            secureRandom.nextBytes(salt);
            byte[] iv = new byte[GCM_IV_LENGTH];
            secureRandom.nextBytes(iv);

            byte[] aesKey = deriveKey(alias, salt);
            Cipher cipher = Cipher.getInstance(AES_GCM);
            cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(aesKey, "AES"), new GCMParameterSpec(GCM_TAG_LENGTH, iv));

            byte[] plaintext = privateKey.getEncoded();
            byte[] ciphertext = cipher.doFinal(plaintext);

            // Format: [salt(16)] + [iv(12)] + [ciphertext]
            byte[] result = new byte[SALT_LENGTH + GCM_IV_LENGTH + ciphertext.length];
            System.arraycopy(salt, 0, result, 0, SALT_LENGTH);
            System.arraycopy(iv, 0, result, SALT_LENGTH, GCM_IV_LENGTH);
            System.arraycopy(ciphertext, 0, result, SALT_LENGTH + GCM_IV_LENGTH, ciphertext.length);
            return new EncryptedPrivateKey(result);
        } catch (Exception e) {
            throw new IllegalStateException("Failed to encrypt private key", e);
        }
    }

    public PrivateKey decrypt(EncryptedPrivateKey encryptedPrivateKey, String alias, String jcaAlgorithm) {
        try {
            byte[] data = encryptedPrivateKey.data();
            byte[] salt = Arrays.copyOfRange(data, 0, SALT_LENGTH);
            byte[] iv = Arrays.copyOfRange(data, SALT_LENGTH, SALT_LENGTH + GCM_IV_LENGTH);
            byte[] ciphertext = Arrays.copyOfRange(data, SALT_LENGTH + GCM_IV_LENGTH, data.length);

            byte[] aesKey = deriveKey(alias, salt);
            Cipher cipher = Cipher.getInstance(AES_GCM);
            cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(aesKey, "AES"), new GCMParameterSpec(GCM_TAG_LENGTH, iv));
            byte[] plaintext = cipher.doFinal(ciphertext);

            PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(plaintext);
            java.security.KeyFactory keyFactory = java.security.KeyFactory.getInstance(jcaAlgorithm, "BC");
            return keyFactory.generatePrivate(keySpec);
        } catch (Exception e) {
            throw new IllegalStateException("Failed to decrypt private key", e);
        }
    }

    private byte[] deriveKey(String alias, byte[] salt) throws Exception {
        String password = keyEncryptionSecret + ":" + alias;
        PBEKeySpec spec = new PBEKeySpec(password.toCharArray(), salt, PBKDF2_ITERATIONS, KEY_LENGTH);
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        return factory.generateSecret(spec).getEncoded();
    }
}
