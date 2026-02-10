package io.dodn.springboot.core.domain.pki.certificate;

import io.dodn.springboot.core.domain.pki.vo.CaId;
import io.dodn.springboot.core.domain.pki.vo.SerialNumber;

import java.util.List;
import java.util.Optional;

public interface IssuedCertificateRepository {

    Optional<IssuedCertificate> findBySerialNumber(SerialNumber sn);

    List<IssuedCertificate> findByIssuerId(CaId issuerId);

    List<IssuedCertificate> findRevokedByIssuerId(CaId issuerId);

    IssuedCertificate save(IssuedCertificate cert);
}
