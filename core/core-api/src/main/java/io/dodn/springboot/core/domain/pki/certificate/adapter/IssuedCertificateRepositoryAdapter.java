package io.dodn.springboot.core.domain.pki.certificate.adapter;

import io.dodn.springboot.core.domain.pki.certificate.IssuedCertificate;
import io.dodn.springboot.core.domain.pki.certificate.IssuedCertificateRepository;
import io.dodn.springboot.core.domain.pki.vo.CaId;
import io.dodn.springboot.core.domain.pki.vo.CertificatePem;
import io.dodn.springboot.core.domain.pki.vo.CertificateValidity;
import io.dodn.springboot.core.domain.pki.vo.CmpTransactionId;
import io.dodn.springboot.core.domain.pki.vo.IssuedCertificateId;
import io.dodn.springboot.core.domain.pki.vo.KeyAlgorithm;
import io.dodn.springboot.core.domain.pki.vo.SerialNumber;
import io.dodn.springboot.core.domain.pki.vo.SubjectDN;
import io.dodn.springboot.core.enums.pki.CertificateStatus;
import io.dodn.springboot.storage.db.core.pki.IssuedCertificateJpaEntity;
import io.dodn.springboot.storage.db.core.pki.IssuedCertificateJpaRepository;
import org.springframework.stereotype.Repository;

import java.math.BigInteger;
import java.util.List;
import java.util.Optional;

@Repository
public class IssuedCertificateRepositoryAdapter implements IssuedCertificateRepository {

    private final IssuedCertificateJpaRepository jpaRepository;

    public IssuedCertificateRepositoryAdapter(IssuedCertificateJpaRepository jpaRepository) {
        this.jpaRepository = jpaRepository;
    }

    @Override
    public Optional<IssuedCertificate> findBySerialNumber(SerialNumber sn) {
        return jpaRepository.findBySerialNumberHex(sn.toHex()).map(this::toDomain);
    }

    @Override
    public List<IssuedCertificate> findByIssuerId(CaId issuerId) {
        return jpaRepository.findByIssuerId(issuerId.value()).stream().map(this::toDomain).toList();
    }

    @Override
    public List<IssuedCertificate> findRevokedByIssuerId(CaId issuerId) {
        return jpaRepository.findByIssuerIdAndStatus(issuerId.value(), CertificateStatus.REVOKED)
                .stream().map(this::toDomain).toList();
    }

    @Override
    public IssuedCertificate save(IssuedCertificate cert) {
        IssuedCertificateJpaEntity entity;
        if (cert.getId() != null) {
            entity = jpaRepository.findById(cert.getId().value()).map(existing -> {
                existing.setStatus(cert.getStatus());
                existing.setRevocationReason(cert.getRevocationReason());
                existing.setRevokedAt(cert.getRevokedAt());
                existing.setCertificatePem(cert.getCertificate() != null ? cert.getCertificate().pem() : null);
                return existing;
            }).orElseGet(() -> toEntity(cert));
        } else {
            entity = toEntity(cert);
        }
        IssuedCertificateJpaEntity saved = jpaRepository.save(entity);
        return toDomain(saved);
    }

    private IssuedCertificate toDomain(IssuedCertificateJpaEntity e) {
        CmpTransactionId txId = null;
        if (e.getCmpTransactionIdHex() != null) {
            try {
                txId = CmpTransactionId.fromHex(e.getCmpTransactionIdHex());
            } catch (Exception ignored) {}
        }

        return new IssuedCertificate(
                IssuedCertificateId.of(e.getId()),
                SerialNumber.of(new BigInteger(e.getSerialNumberHex(), 16)),
                new SubjectDN(e.getSubjectDnCn(), e.getSubjectDnO(), e.getSubjectDnOu(),
                        e.getSubjectDnC(), e.getSubjectDnSt(), e.getSubjectDnL()),
                CaId.of(e.getIssuerId()),
                e.getCertificatePem() != null ? new CertificatePem(e.getCertificatePem()) : null,
                new KeyAlgorithm(e.getKeyAlgorithmType()),
                new CertificateValidity(e.getNotBefore(), e.getNotAfter()),
                e.getStatus(),
                e.getRevocationReason(),
                e.getRevokedAt(),
                txId
        );
    }

    private IssuedCertificateJpaEntity toEntity(IssuedCertificate cert) {
        String txIdHex = cert.getCmpTransactionId() != null ? cert.getCmpTransactionId().toHex() : null;
        return new IssuedCertificateJpaEntity(
                cert.getSerialNumber().toHex(),
                cert.getSubjectDN().cn(),
                cert.getSubjectDN().o(),
                cert.getSubjectDN().ou(),
                cert.getSubjectDN().c(),
                cert.getSubjectDN().st(),
                cert.getSubjectDN().l(),
                cert.getIssuerId().value(),
                cert.getCertificate() != null ? cert.getCertificate().pem() : null,
                cert.getKeyAlgorithm().type(),
                cert.getValidity().notBefore(),
                cert.getValidity().notAfter(),
                cert.getStatus(),
                cert.getRevocationReason(),
                cert.getRevokedAt(),
                txIdHex
        );
    }
}
