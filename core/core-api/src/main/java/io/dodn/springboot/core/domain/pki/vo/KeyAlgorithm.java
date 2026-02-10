package io.dodn.springboot.core.domain.pki.vo;

import io.dodn.springboot.core.enums.pki.KeyAlgorithmType;

public record KeyAlgorithm(KeyAlgorithmType type) {

    public KeyAlgorithm {
        if (type == null) {
            throw new IllegalArgumentException("KeyAlgorithmType must not be null");
        }
    }

    public String getJcaAlgorithm() {
        return switch (type) {
            case RSA_2048, RSA_4096 -> "RSA";
            case EC_P256, EC_P384 -> "EC";
        };
    }

    public Integer getKeySize() {
        return switch (type) {
            case RSA_2048 -> 2048;
            case RSA_4096 -> 4096;
            case EC_P256, EC_P384 -> null;
        };
    }

    public String getCurveName() {
        return switch (type) {
            case RSA_2048, RSA_4096 -> null;
            case EC_P256 -> "P-256";
            case EC_P384 -> "P-384";
        };
    }

    public String toSignatureAlgorithm() {
        return switch (type) {
            case RSA_2048 -> "SHA256withRSA";
            case RSA_4096 -> "SHA512withRSA";
            case EC_P256 -> "SHA256withECDSA";
            case EC_P384 -> "SHA384withECDSA";
        };
    }
}
