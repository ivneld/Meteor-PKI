package io.dodn.springboot.storage.db.core.pki;

import io.dodn.springboot.core.enums.pki.CertificateStatus;
import io.dodn.springboot.core.enums.pki.KeyAlgorithmType;
import io.dodn.springboot.core.enums.pki.RevocationReason;
import io.dodn.springboot.storage.db.core.BaseEntity;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.Table;

import java.time.Instant;

@Entity
@Table(name = "issued_certificate")
public class IssuedCertificateJpaEntity extends BaseEntity {

    @Column(nullable = false, unique = true, length = 100)
    private String serialNumberHex;

    @Column(nullable = false, length = 500)
    private String subjectDnCn;

    @Column(length = 200)
    private String subjectDnO;

    @Column(length = 200)
    private String subjectDnOu;

    @Column(length = 10)
    private String subjectDnC;

    @Column(length = 200)
    private String subjectDnSt;

    @Column(length = 200)
    private String subjectDnL;

    @Column(nullable = false)
    private Long issuerId;

    @Column(columnDefinition = "TEXT")
    private String certificatePem;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 20)
    private KeyAlgorithmType keyAlgorithmType;

    @Column(nullable = false)
    private Instant notBefore;

    @Column(nullable = false)
    private Instant notAfter;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 20)
    private CertificateStatus status;

    @Enumerated(EnumType.STRING)
    @Column(length = 30)
    private RevocationReason revocationReason;

    @Column
    private Instant revokedAt;

    @Column(length = 64)
    private String cmpTransactionIdHex;

    protected IssuedCertificateJpaEntity() {}

    public IssuedCertificateJpaEntity(String serialNumberHex, String subjectDnCn, String subjectDnO,
            String subjectDnOu, String subjectDnC, String subjectDnSt, String subjectDnL,
            Long issuerId, String certificatePem, KeyAlgorithmType keyAlgorithmType,
            Instant notBefore, Instant notAfter, CertificateStatus status,
            RevocationReason revocationReason, Instant revokedAt, String cmpTransactionIdHex) {
        this.serialNumberHex = serialNumberHex;
        this.subjectDnCn = subjectDnCn;
        this.subjectDnO = subjectDnO;
        this.subjectDnOu = subjectDnOu;
        this.subjectDnC = subjectDnC;
        this.subjectDnSt = subjectDnSt;
        this.subjectDnL = subjectDnL;
        this.issuerId = issuerId;
        this.certificatePem = certificatePem;
        this.keyAlgorithmType = keyAlgorithmType;
        this.notBefore = notBefore;
        this.notAfter = notAfter;
        this.status = status;
        this.revocationReason = revocationReason;
        this.revokedAt = revokedAt;
        this.cmpTransactionIdHex = cmpTransactionIdHex;
    }

    public String getSerialNumberHex() { return serialNumberHex; }
    public String getSubjectDnCn() { return subjectDnCn; }
    public String getSubjectDnO() { return subjectDnO; }
    public String getSubjectDnOu() { return subjectDnOu; }
    public String getSubjectDnC() { return subjectDnC; }
    public String getSubjectDnSt() { return subjectDnSt; }
    public String getSubjectDnL() { return subjectDnL; }
    public Long getIssuerId() { return issuerId; }
    public String getCertificatePem() { return certificatePem; }
    public void setCertificatePem(String pem) { this.certificatePem = pem; }
    public KeyAlgorithmType getKeyAlgorithmType() { return keyAlgorithmType; }
    public Instant getNotBefore() { return notBefore; }
    public Instant getNotAfter() { return notAfter; }
    public CertificateStatus getStatus() { return status; }
    public void setStatus(CertificateStatus status) { this.status = status; }
    public RevocationReason getRevocationReason() { return revocationReason; }
    public void setRevocationReason(RevocationReason reason) { this.revocationReason = reason; }
    public Instant getRevokedAt() { return revokedAt; }
    public void setRevokedAt(Instant revokedAt) { this.revokedAt = revokedAt; }
    public String getCmpTransactionIdHex() { return cmpTransactionIdHex; }
}
