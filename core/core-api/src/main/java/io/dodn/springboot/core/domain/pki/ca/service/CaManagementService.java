package io.dodn.springboot.core.domain.pki.ca.service;

import io.dodn.springboot.core.domain.pki.ca.CaAlias;
import io.dodn.springboot.core.domain.pki.ca.CaRepository;
import io.dodn.springboot.core.domain.pki.ca.CertificateAuthority;
import io.dodn.springboot.core.domain.pki.certificate.IssuedCertificateRepository;
import io.dodn.springboot.core.domain.pki.crypto.CaKeyService;
import io.dodn.springboot.core.domain.pki.crypto.CertificateBuilderService;
import io.dodn.springboot.core.domain.pki.crypto.CrlBuilderService;
import io.dodn.springboot.core.domain.pki.vo.CaChainDepth;
import io.dodn.springboot.core.domain.pki.vo.CaId;
import io.dodn.springboot.core.domain.pki.vo.CertificatePem;
import io.dodn.springboot.core.domain.pki.vo.CertificateValidity;
import io.dodn.springboot.core.domain.pki.vo.CrlDistributionPoint;
import io.dodn.springboot.core.domain.pki.vo.EncryptedPrivateKey;
import io.dodn.springboot.core.domain.pki.vo.SerialNumber;
import io.dodn.springboot.core.enums.pki.CaStatus;
import io.dodn.springboot.core.enums.pki.CaType;
import io.dodn.springboot.core.support.error.CoreException;
import io.dodn.springboot.core.support.error.ErrorType;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.util.ArrayList;
import java.util.List;

@Service
public class CaManagementService {

    private final CaRepository caRepository;
    private final IssuedCertificateRepository issuedCertificateRepository;
    private final CaKeyService caKeyService;
    private final CertificateBuilderService certBuilderService;
    private final CrlBuilderService crlBuilderService;
    private final String crlBaseUrl;
    private final int rootCaValidityDays;
    private final int subCaValidityDays;

    public CaManagementService(CaRepository caRepository,
            IssuedCertificateRepository issuedCertificateRepository,
            CaKeyService caKeyService,
            CertificateBuilderService certBuilderService,
            CrlBuilderService crlBuilderService,
            @Value("${pki.crl-distribution-base-url}") String crlBaseUrl,
            @Value("${pki.default-validity-days.root-ca}") int rootCaValidityDays,
            @Value("${pki.default-validity-days.sub-ca}") int subCaValidityDays) {
        this.caRepository = caRepository;
        this.issuedCertificateRepository = issuedCertificateRepository;
        this.caKeyService = caKeyService;
        this.certBuilderService = certBuilderService;
        this.crlBuilderService = crlBuilderService;
        this.crlBaseUrl = crlBaseUrl;
        this.rootCaValidityDays = rootCaValidityDays;
        this.subCaValidityDays = subCaValidityDays;
    }

    public CertificateAuthority createRootCa(CreateRootCaCommand command) {
        CaAlias alias = CaAlias.of(command.alias());
        if (caRepository.existsByAlias(alias)) {
            throw new CoreException(ErrorType.PKI_CA_ALIAS_DUPLICATE, command.alias());
        }

        KeyPair keyPair = caKeyService.generateKeyPair(command.keyAlgorithm());
        SerialNumber serialNumber = SerialNumber.generate();
        CertificateValidity validity = CertificateValidity.forDays(rootCaValidityDays);
        CrlDistributionPoint crlDp = new CrlDistributionPoint(crlBaseUrl + "/pki/" + command.alias() + "/crl");

        EncryptedPrivateKey encPrivKey = caKeyService.encrypt(keyPair.getPrivate(), command.alias());

        CertificateAuthority ca = new CertificateAuthority(
                null, alias, command.subjectDN(), CaType.ROOT,
                command.keyAlgorithm(), null, encPrivKey, null,
                serialNumber, validity, CaStatus.ACTIVE, crlDp, CaChainDepth.unlimited()
        );

        CertificatePem certPem = certBuilderService.buildRootCaCertificate(
                command.subjectDN(), serialNumber, validity, keyPair.getPublic(),
                keyPair.getPrivate(), crlDp, command.keyAlgorithm().toSignatureAlgorithm()
        );
        ca.setCertificate(certPem);

        return caRepository.save(ca);
    }

    public CertificateAuthority createSubCa(CreateSubCaCommand command) {
        CaAlias alias = CaAlias.of(command.alias());
        if (caRepository.existsByAlias(alias)) {
            throw new CoreException(ErrorType.PKI_CA_ALIAS_DUPLICATE, command.alias());
        }

        CertificateAuthority parentCa = caRepository.findById(command.parentId())
                .orElseThrow(() -> new CoreException(ErrorType.PKI_CA_NOT_FOUND, command.parentId()));
        if (!parentCa.canIssue()) {
            throw new CoreException(ErrorType.PKI_CA_NOT_ACTIVE, parentCa.getAlias().value());
        }

        KeyPair keyPair = caKeyService.generateKeyPair(command.keyAlgorithm());
        SerialNumber serialNumber = SerialNumber.generate();
        CertificateValidity validity = CertificateValidity.forDays(subCaValidityDays);
        CrlDistributionPoint crlDp = new CrlDistributionPoint(crlBaseUrl + "/pki/" + command.alias() + "/crl");
        CaChainDepth chainDepth = parentCa.maxIssuableDepth();

        EncryptedPrivateKey encPrivKey = caKeyService.encrypt(keyPair.getPrivate(), command.alias());
        PrivateKey parentPrivKey = caKeyService.decrypt(parentCa.getPrivateKey(),
                parentCa.getAlias().value(), parentCa.getKeyAlgorithm().getJcaAlgorithm());

        String aiaUrl = crlBaseUrl + "/api/v1/pki/ca/" + parentCa.getId().value() + "/certificate";

        CertificatePem certPem = certBuilderService.buildSubCaCertificate(
                command.subjectDN(), serialNumber, validity, keyPair.getPublic(),
                chainDepth, parentCa, parentPrivKey, crlDp, aiaUrl
        );

        CaType type = chainDepth.pathLen() == 0 ? CaType.END_ENTITY_ISSUER : CaType.INTERMEDIATE;

        CertificateAuthority ca = new CertificateAuthority(
                null, alias, command.subjectDN(), type,
                command.keyAlgorithm(), parentCa.getId(), encPrivKey, certPem,
                serialNumber, validity, CaStatus.ACTIVE, crlDp, chainDepth
        );

        return caRepository.save(ca);
    }

    public List<CertificateAuthority> getCaChain(CaId caId) {
        CertificateAuthority ca = caRepository.findById(caId)
                .orElseThrow(() -> new CoreException(ErrorType.PKI_CA_NOT_FOUND, caId));
        List<CertificateAuthority> chain = new ArrayList<>();
        CertificateAuthority current = ca;
        while (current != null) {
            chain.add(0, current);
            if (current.isRoot()) {
                break;
            }
            current = caRepository.findById(current.getParentId()).orElse(null);
        }
        return chain;
    }

    public byte[] generateCrl(CaId caId) {
        CertificateAuthority ca = caRepository.findById(caId)
                .orElseThrow(() -> new CoreException(ErrorType.PKI_CA_NOT_FOUND, caId));
        PrivateKey privateKey = caKeyService.decrypt(ca.getPrivateKey(),
                ca.getAlias().value(), ca.getKeyAlgorithm().getJcaAlgorithm());
        var revokedCerts = issuedCertificateRepository.findRevokedByIssuerId(ca.getId());
        return crlBuilderService.buildCrl(ca, revokedCerts, privateKey);
    }

    public List<CertificateAuthority> findAll() {
        return caRepository.findAll();
    }

    public CertificateAuthority findById(CaId id) {
        return caRepository.findById(id)
                .orElseThrow(() -> new CoreException(ErrorType.PKI_CA_NOT_FOUND, id));
    }
}
