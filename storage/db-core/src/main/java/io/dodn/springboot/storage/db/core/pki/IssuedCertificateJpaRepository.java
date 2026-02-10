package io.dodn.springboot.storage.db.core.pki;

import io.dodn.springboot.core.enums.pki.CertificateStatus;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.Optional;

public interface IssuedCertificateJpaRepository extends JpaRepository<IssuedCertificateJpaEntity, Long> {

    Optional<IssuedCertificateJpaEntity> findBySerialNumberHex(String serialNumberHex);

    List<IssuedCertificateJpaEntity> findByIssuerId(Long issuerId);

    List<IssuedCertificateJpaEntity> findByIssuerIdAndStatus(Long issuerId, CertificateStatus status);
}
