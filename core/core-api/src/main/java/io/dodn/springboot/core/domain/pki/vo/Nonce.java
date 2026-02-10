package io.dodn.springboot.core.domain.pki.vo;

import java.security.SecureRandom;
import java.util.Arrays;
import java.util.HexFormat;

public record Nonce(byte[] value) {

    private static final int LENGTH = 16;
    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    public Nonce {
        if (value == null || value.length == 0) {
            throw new IllegalArgumentException("Nonce value must not be empty");
        }
        value = Arrays.copyOf(value, value.length);
    }

    public static Nonce generate() {
        byte[] bytes = new byte[LENGTH];
        SECURE_RANDOM.nextBytes(bytes);
        return new Nonce(bytes);
    }

    public static Nonce fromBytes(byte[] b) {
        return new Nonce(b);
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
        if (!(o instanceof Nonce that)) return false;
        return Arrays.equals(value, that.value);
    }

    @Override
    public int hashCode() {
        return Arrays.hashCode(value);
    }

    @Override
    public String toString() {
        return "Nonce[" + toHex() + "]";
    }
}
