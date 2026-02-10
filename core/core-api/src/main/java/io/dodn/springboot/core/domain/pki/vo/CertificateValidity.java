package io.dodn.springboot.core.domain.pki.vo;

import java.time.Instant;
import java.time.temporal.ChronoUnit;

public record CertificateValidity(Instant notBefore, Instant notAfter) {

    public CertificateValidity {
        if (notBefore == null || notAfter == null) {
            throw new IllegalArgumentException("notBefore and notAfter must not be null");
        }
        if (!notBefore.isBefore(notAfter)) {
            throw new IllegalArgumentException("notBefore must be before notAfter");
        }
    }

    public boolean isValid() {
        Instant now = Instant.now();
        return now.isAfter(notBefore) && now.isBefore(notAfter);
    }

    public boolean isExpired() {
        return Instant.now().isAfter(notAfter);
    }

    public boolean contains(Instant t) {
        return !t.isBefore(notBefore) && !t.isAfter(notAfter);
    }

    public static CertificateValidity forYears(int years) {
        Instant notBefore = Instant.now();
        Instant notAfter = notBefore.plus(years * 365L, ChronoUnit.DAYS);
        return new CertificateValidity(notBefore, notAfter);
    }

    public static CertificateValidity forDays(int days) {
        Instant notBefore = Instant.now();
        Instant notAfter = notBefore.plus(days, ChronoUnit.DAYS);
        return new CertificateValidity(notBefore, notAfter);
    }
}
