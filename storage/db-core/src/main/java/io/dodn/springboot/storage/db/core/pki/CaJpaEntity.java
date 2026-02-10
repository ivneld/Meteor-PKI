package io.dodn.springboot.storage.db.core.pki;

import io.dodn.springboot.core.enums.pki.CaStatus;
import io.dodn.springboot.core.enums.pki.CaType;
import io.dodn.springboot.core.enums.pki.KeyAlgorithmType;
import io.dodn.springboot.storage.db.core.BaseEntity;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.Table;

import java.time.Instant;

@Entity
@Table(name = "certificate_authority")
public class CaJpaEntity extends BaseEntity {

    @Column(nullable = false, unique = true, length = 100)
    private String alias;

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

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 30)
    private CaType type;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 20)
    private KeyAlgorithmType keyAlgorithmType;

    @Column
    private Long parentId;

    @Column(nullable = false, columnDefinition = "TEXT")
    private String encryptedPrivateKeyBase64;

    @Column(columnDefinition = "TEXT")
    private String certificatePem;

    @Column(nullable = false, length = 100)
    private String serialNumberHex;

    @Column(nullable = false)
    private Instant notBefore;

    @Column(nullable = false)
    private Instant notAfter;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 20)
    private CaStatus status;

    @Column(length = 500)
    private String crlDistributionPointUrl;

    @Column(nullable = false)
    private int chainDepthPathLen;

    protected CaJpaEntity() {}

    public CaJpaEntity(String alias, String subjectDnCn, String subjectDnO, String subjectDnOu,
            String subjectDnC, String subjectDnSt, String subjectDnL, CaType type,
            KeyAlgorithmType keyAlgorithmType, Long parentId, String encryptedPrivateKeyBase64,
            String certificatePem, String serialNumberHex, Instant notBefore, Instant notAfter,
            CaStatus status, String crlDistributionPointUrl, int chainDepthPathLen) {
        this.alias = alias;
        this.subjectDnCn = subjectDnCn;
        this.subjectDnO = subjectDnO;
        this.subjectDnOu = subjectDnOu;
        this.subjectDnC = subjectDnC;
        this.subjectDnSt = subjectDnSt;
        this.subjectDnL = subjectDnL;
        this.type = type;
        this.keyAlgorithmType = keyAlgorithmType;
        this.parentId = parentId;
        this.encryptedPrivateKeyBase64 = encryptedPrivateKeyBase64;
        this.certificatePem = certificatePem;
        this.serialNumberHex = serialNumberHex;
        this.notBefore = notBefore;
        this.notAfter = notAfter;
        this.status = status;
        this.crlDistributionPointUrl = crlDistributionPointUrl;
        this.chainDepthPathLen = chainDepthPathLen;
    }

    public String getAlias() { return alias; }
    public String getSubjectDnCn() { return subjectDnCn; }
    public String getSubjectDnO() { return subjectDnO; }
    public String getSubjectDnOu() { return subjectDnOu; }
    public String getSubjectDnC() { return subjectDnC; }
    public String getSubjectDnSt() { return subjectDnSt; }
    public String getSubjectDnL() { return subjectDnL; }
    public CaType getType() { return type; }
    public KeyAlgorithmType getKeyAlgorithmType() { return keyAlgorithmType; }
    public Long getParentId() { return parentId; }
    public String getEncryptedPrivateKeyBase64() { return encryptedPrivateKeyBase64; }
    public String getCertificatePem() { return certificatePem; }
    public void setCertificatePem(String certificatePem) { this.certificatePem = certificatePem; }
    public String getSerialNumberHex() { return serialNumberHex; }
    public Instant getNotBefore() { return notBefore; }
    public Instant getNotAfter() { return notAfter; }
    public CaStatus getStatus() { return status; }
    public void setStatus(CaStatus status) { this.status = status; }
    public String getCrlDistributionPointUrl() { return crlDistributionPointUrl; }
    public int getChainDepthPathLen() { return chainDepthPathLen; }
}
