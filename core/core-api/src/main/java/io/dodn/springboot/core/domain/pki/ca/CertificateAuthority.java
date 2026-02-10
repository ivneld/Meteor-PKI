package io.dodn.springboot.core.domain.pki.ca;

import io.dodn.springboot.core.domain.pki.vo.CaChainDepth;
import io.dodn.springboot.core.domain.pki.vo.CaId;
import io.dodn.springboot.core.domain.pki.vo.CertificatePem;
import io.dodn.springboot.core.domain.pki.vo.CertificateValidity;
import io.dodn.springboot.core.domain.pki.vo.CrlDistributionPoint;
import io.dodn.springboot.core.domain.pki.vo.EncryptedPrivateKey;
import io.dodn.springboot.core.domain.pki.vo.KeyAlgorithm;
import io.dodn.springboot.core.domain.pki.vo.SerialNumber;
import io.dodn.springboot.core.domain.pki.vo.SubjectDN;
import io.dodn.springboot.core.enums.pki.CaStatus;
import io.dodn.springboot.core.enums.pki.CaType;

public class CertificateAuthority {

    private CaId id;
    private CaAlias alias;
    private SubjectDN subjectDN;
    private CaType type;
    private KeyAlgorithm keyAlgorithm;
    private CaId parentId;
    private EncryptedPrivateKey privateKey;
    private CertificatePem certificate;
    private SerialNumber serialNumber;
    private CertificateValidity validity;
    private CaStatus status;
    private CrlDistributionPoint crlDp;
    private CaChainDepth chainDepth;

    public CertificateAuthority(CaId id, CaAlias alias, SubjectDN subjectDN, CaType type,
            KeyAlgorithm keyAlgorithm, CaId parentId, EncryptedPrivateKey privateKey,
            CertificatePem certificate, SerialNumber serialNumber, CertificateValidity validity,
            CaStatus status, CrlDistributionPoint crlDp, CaChainDepth chainDepth) {
        this.id = id;
        this.alias = alias;
        this.subjectDN = subjectDN;
        this.type = type;
        this.keyAlgorithm = keyAlgorithm;
        this.parentId = parentId;
        this.privateKey = privateKey;
        this.certificate = certificate;
        this.serialNumber = serialNumber;
        this.validity = validity;
        this.status = status;
        this.crlDp = crlDp;
        this.chainDepth = chainDepth;
    }

    public boolean isRoot() {
        return parentId == null;
    }

    public boolean canIssue() {
        return status == CaStatus.ACTIVE && !isExpired();
    }

    public boolean isExpired() {
        return validity.isExpired();
    }

    public void activate() {
        this.status = CaStatus.ACTIVE;
    }

    public void revoke() {
        this.status = CaStatus.REVOKED;
    }

    public CaChainDepth maxIssuableDepth() {
        if (chainDepth.isUnlimited()) {
            return CaChainDepth.unlimited();
        }
        return CaChainDepth.of(chainDepth.pathLen() - 1);
    }

    public CaId getId() { return id; }
    public void setId(CaId id) { this.id = id; }
    public CaAlias getAlias() { return alias; }
    public SubjectDN getSubjectDN() { return subjectDN; }
    public CaType getType() { return type; }
    public KeyAlgorithm getKeyAlgorithm() { return keyAlgorithm; }
    public CaId getParentId() { return parentId; }
    public EncryptedPrivateKey getPrivateKey() { return privateKey; }
    public CertificatePem getCertificate() { return certificate; }
    public void setCertificate(CertificatePem certificate) { this.certificate = certificate; }
    public SerialNumber getSerialNumber() { return serialNumber; }
    public CertificateValidity getValidity() { return validity; }
    public CaStatus getStatus() { return status; }
    public CrlDistributionPoint getCrlDp() { return crlDp; }
    public CaChainDepth getChainDepth() { return chainDepth; }
}
