package io.dodn.springboot.core.domain.pki.certificate.service;

import io.dodn.springboot.core.domain.pki.ca.CaRepository;
import io.dodn.springboot.core.domain.pki.ca.CertificateAuthority;
import io.dodn.springboot.core.domain.pki.certificate.IssuedCertificate;
import io.dodn.springboot.core.domain.pki.certificate.IssuedCertificateRepository;
import io.dodn.springboot.core.domain.pki.crypto.CaKeyService;
import io.dodn.springboot.core.domain.pki.crypto.CertificateBuilderService;
import io.dodn.springboot.core.domain.pki.vo.CaId;
import io.dodn.springboot.core.domain.pki.vo.CertificatePem;
import io.dodn.springboot.core.domain.pki.vo.CertificateValidity;
import io.dodn.springboot.core.domain.pki.vo.IssuedCertificateId;
import io.dodn.springboot.core.domain.pki.vo.SerialNumber;
import io.dodn.springboot.core.enums.pki.CertificateStatus;
import io.dodn.springboot.core.enums.pki.RevocationReason;
import io.dodn.springboot.core.support.error.CoreException;
import io.dodn.springboot.core.support.error.ErrorType;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.security.PrivateKey;

@Service
public class CertificateIssuanceService {

    private final CaRepository caRepository;
    private final IssuedCertificateRepository issuedCertificateRepository;
    private final CaKeyService caKeyService;
    private final CertificateBuilderService certBuilderService;
    private final String crlBaseUrl;
    private final int endEntityValidityDays;

    public CertificateIssuanceService(CaRepository caRepository,
            IssuedCertificateRepository issuedCertificateRepository,
            CaKeyService caKeyService,
            CertificateBuilderService certBuilderService,
            @Value("${pki.crl-distribution-base-url}") String crlBaseUrl,
            @Value("${pki.default-validity-days.end-entity}") int endEntityValidityDays) {
        this.caRepository = caRepository;
        this.issuedCertificateRepository = issuedCertificateRepository;
        this.caKeyService = caKeyService;
        this.certBuilderService = certBuilderService;
        this.crlBaseUrl = crlBaseUrl;
        this.endEntityValidityDays = endEntityValidityDays;
    }

    public IssuedCertificate issueCertificate(IssueCertificateCommand command, CaId caId) {
        CertificateAuthority issuer = caRepository.findById(caId)
                .orElseThrow(() -> new CoreException(ErrorType.PKI_CA_NOT_FOUND, caId));
        if (!issuer.canIssue()) {
            throw new CoreException(ErrorType.PKI_CA_NOT_ACTIVE, issuer.getAlias().value());
        }

        PrivateKey issuerPrivKey = caKeyService.decrypt(issuer.getPrivateKey(),
                issuer.getAlias().value(), issuer.getKeyAlgorithm().getJcaAlgorithm());

        SerialNumber serialNumber = SerialNumber.generate();
        CertificateValidity validity = CertificateValidity.forDays(endEntityValidityDays);
        String aiaUrl = crlBaseUrl + "/api/v1/pki/ca/" + issuer.getId().value() + "/certificate";

        CertificatePem certPem = certBuilderService.buildEndEntityCertificate(
                command.subjectDN(), serialNumber, validity, command.publicKey(),
                command.keyUsage(), command.extKeyUsage(), command.san(),
                issuer, issuerPrivKey, issuer.getCrlDp(), aiaUrl
        );

        IssuedCertificate issuedCert = new IssuedCertificate(
                null, serialNumber, command.subjectDN(), issuer.getId(), certPem,
                issuer.getKeyAlgorithm(), validity, CertificateStatus.VALID,
                null, null, command.cmpTransactionId()
        );

        return issuedCertificateRepository.save(issuedCert);
    }

    public IssuedCertificate revokeCertificate(SerialNumber serialNumber, CaId caId, RevocationReason reason) {
        IssuedCertificate cert = issuedCertificateRepository.findBySerialNumber(serialNumber)
                .orElseThrow(() -> new CoreException(ErrorType.PKI_CERT_NOT_FOUND, serialNumber.toHex()));
        if (!cert.getIssuerId().equals(caId)) {
            throw new CoreException(ErrorType.PKI_CERT_NOT_FOUND, serialNumber.toHex());
        }
        if (cert.isRevoked()) {
            throw new CoreException(ErrorType.PKI_CERT_ALREADY_REVOKED, serialNumber.toHex());
        }
        cert.revoke(reason);
        return issuedCertificateRepository.save(cert);
    }
}
