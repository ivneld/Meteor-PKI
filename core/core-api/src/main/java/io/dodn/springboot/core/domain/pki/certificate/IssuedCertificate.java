package io.dodn.springboot.core.domain.pki.certificate;

import io.dodn.springboot.core.domain.pki.vo.CaId;
import io.dodn.springboot.core.domain.pki.vo.CertificatePem;
import io.dodn.springboot.core.domain.pki.vo.CertificateValidity;
import io.dodn.springboot.core.domain.pki.vo.CmpTransactionId;
import io.dodn.springboot.core.domain.pki.vo.IssuedCertificateId;
import io.dodn.springboot.core.domain.pki.vo.KeyAlgorithm;
import io.dodn.springboot.core.domain.pki.vo.SerialNumber;
import io.dodn.springboot.core.domain.pki.vo.SubjectDN;
import io.dodn.springboot.core.enums.pki.CertificateStatus;
import io.dodn.springboot.core.enums.pki.RevocationReason;

import java.time.Instant;

public class IssuedCertificate {

    private IssuedCertificateId id;
    private SerialNumber serialNumber;
    private SubjectDN subjectDN;
    private CaId issuerId;
    private CertificatePem certificate;
    private KeyAlgorithm keyAlgorithm;
    private CertificateValidity validity;
    private CertificateStatus status;
    private RevocationReason revocationReason;
    private Instant revokedAt;
    private CmpTransactionId cmpTransactionId;

    public IssuedCertificate(IssuedCertificateId id, SerialNumber serialNumber, SubjectDN subjectDN,
            CaId issuerId, CertificatePem certificate, KeyAlgorithm keyAlgorithm,
            CertificateValidity validity, CertificateStatus status,
            RevocationReason revocationReason, Instant revokedAt, CmpTransactionId cmpTransactionId) {
        this.id = id;
        this.serialNumber = serialNumber;
        this.subjectDN = subjectDN;
        this.issuerId = issuerId;
        this.certificate = certificate;
        this.keyAlgorithm = keyAlgorithm;
        this.validity = validity;
        this.status = status;
        this.revocationReason = revocationReason;
        this.revokedAt = revokedAt;
        this.cmpTransactionId = cmpTransactionId;
    }

    public boolean isRevoked() {
        return status == CertificateStatus.REVOKED;
    }

    public boolean isExpired() {
        return validity.isExpired();
    }

    public boolean isValid() {
        return status == CertificateStatus.VALID && validity.isValid();
    }

    public void revoke(RevocationReason reason) {
        this.status = CertificateStatus.REVOKED;
        this.revocationReason = reason;
        this.revokedAt = Instant.now();
    }

    public IssuedCertificateId getId() { return id; }
    public void setId(IssuedCertificateId id) { this.id = id; }
    public SerialNumber getSerialNumber() { return serialNumber; }
    public SubjectDN getSubjectDN() { return subjectDN; }
    public CaId getIssuerId() { return issuerId; }
    public CertificatePem getCertificate() { return certificate; }
    public void setCertificate(CertificatePem certificate) { this.certificate = certificate; }
    public KeyAlgorithm getKeyAlgorithm() { return keyAlgorithm; }
    public CertificateValidity getValidity() { return validity; }
    public CertificateStatus getStatus() { return status; }
    public RevocationReason getRevocationReason() { return revocationReason; }
    public Instant getRevokedAt() { return revokedAt; }
    public CmpTransactionId getCmpTransactionId() { return cmpTransactionId; }
}
