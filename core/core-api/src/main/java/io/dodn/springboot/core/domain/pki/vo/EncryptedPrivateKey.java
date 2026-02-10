package io.dodn.springboot.core.domain.pki.vo;

import java.util.Arrays;
import java.util.Base64;

public record EncryptedPrivateKey(byte[] data) {

    public EncryptedPrivateKey {
        if (data == null || data.length == 0) {
            throw new IllegalArgumentException("EncryptedPrivateKey data must not be empty");
        }
        data = Arrays.copyOf(data, data.length);
    }

    public String toBase64() {
        return Base64.getEncoder().encodeToString(data);
    }

    public static EncryptedPrivateKey fromBase64(String b64) {
        return new EncryptedPrivateKey(Base64.getDecoder().decode(b64));
    }

    @Override
    public byte[] data() {
        return Arrays.copyOf(data, data.length);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof EncryptedPrivateKey that)) return false;
        return Arrays.equals(data, that.data);
    }

    @Override
    public int hashCode() {
        return Arrays.hashCode(data);
    }

    @Override
    public String toString() {
        return "EncryptedPrivateKey[<redacted>]";
    }
}
