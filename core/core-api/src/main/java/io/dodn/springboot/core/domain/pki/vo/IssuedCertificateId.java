package io.dodn.springboot.core.domain.pki.vo;

public record IssuedCertificateId(Long value) {

    public IssuedCertificateId {
        if (value == null) {
            throw new IllegalArgumentException("IssuedCertificateId value must not be null");
        }
    }

    public static IssuedCertificateId of(Long value) {
        return new IssuedCertificateId(value);
    }
}
