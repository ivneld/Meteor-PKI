package io.dodn.springboot.core.domain.pki.vo;

import java.math.BigInteger;
import java.security.SecureRandom;

public record SerialNumber(BigInteger value) {

    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    public SerialNumber {
        if (value == null || value.signum() <= 0) {
            throw new IllegalArgumentException("SerialNumber must be a positive BigInteger");
        }
    }

    public static SerialNumber generate() {
        return new SerialNumber(new BigInteger(128, SECURE_RANDOM).abs().add(BigInteger.ONE));
    }

    public static SerialNumber of(BigInteger v) {
        return new SerialNumber(v);
    }

    public String toHex() {
        return value.toString(16);
    }
}
