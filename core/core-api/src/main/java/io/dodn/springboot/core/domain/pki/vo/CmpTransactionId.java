package io.dodn.springboot.core.domain.pki.vo;

import java.security.SecureRandom;
import java.util.Arrays;
import java.util.HexFormat;

public record CmpTransactionId(byte[] value) {

    private static final int LENGTH = 16;
    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    public CmpTransactionId {
        if (value == null || value.length != LENGTH) {
            throw new IllegalArgumentException("CmpTransactionId must be exactly 16 bytes");
        }
        value = Arrays.copyOf(value, value.length);
    }

    public static CmpTransactionId generate() {
        byte[] bytes = new byte[LENGTH];
        SECURE_RANDOM.nextBytes(bytes);
        return new CmpTransactionId(bytes);
    }

    public static CmpTransactionId fromHex(String hex) {
        return new CmpTransactionId(HexFormat.of().parseHex(hex));
    }

    public String toHex() {
        return HexFormat.of().formatHex(value);
    }

    @Override
    public byte[] value() {
        return Arrays.copyOf(value, value.length);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof CmpTransactionId that)) return false;
        return Arrays.equals(value, that.value);
    }

    @Override
    public int hashCode() {
        return Arrays.hashCode(value);
    }

    @Override
    public String toString() {
        return "CmpTransactionId[" + toHex() + "]";
    }
}
