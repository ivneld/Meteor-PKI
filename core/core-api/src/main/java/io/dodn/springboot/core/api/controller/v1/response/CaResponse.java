package io.dodn.springboot.core.api.controller.v1.response;

import io.dodn.springboot.core.domain.pki.ca.CertificateAuthority;
import io.dodn.springboot.core.enums.pki.CaStatus;
import io.dodn.springboot.core.enums.pki.CaType;
import io.dodn.springboot.core.enums.pki.KeyAlgorithmType;

import java.time.Instant;

public record CaResponse(
        Long id,
        String alias,
        String subjectDn,
        CaType type,
        KeyAlgorithmType keyAlgorithmType,
        Long parentId,
        String serialNumber,
        Instant notBefore,
        Instant notAfter,
        CaStatus status,
        String crlDistributionPointUrl
) {
    public static CaResponse from(CertificateAuthority ca) {
        return new CaResponse(
                ca.getId().value(),
                ca.getAlias().value(),
                ca.getSubjectDN().toRfc2253(),
                ca.getType(),
                ca.getKeyAlgorithm().type(),
                ca.getParentId() != null ? ca.getParentId().value() : null,
                ca.getSerialNumber().toHex(),
                ca.getValidity().notBefore(),
                ca.getValidity().notAfter(),
                ca.getStatus(),
                ca.getCrlDp() != null ? ca.getCrlDp().url() : null
        );
    }
}
