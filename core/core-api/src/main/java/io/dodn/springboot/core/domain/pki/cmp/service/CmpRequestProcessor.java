package io.dodn.springboot.core.domain.pki.cmp.service;

import io.dodn.springboot.core.domain.pki.ca.CaAlias;
import io.dodn.springboot.core.domain.pki.ca.CaRepository;
import io.dodn.springboot.core.domain.pki.ca.CertificateAuthority;
import io.dodn.springboot.core.domain.pki.certificate.IssuedCertificate;
import io.dodn.springboot.core.domain.pki.certificate.IssuedCertificateRepository;
import io.dodn.springboot.core.domain.pki.certificate.service.CertificateIssuanceService;
import io.dodn.springboot.core.domain.pki.certificate.service.IssueCertificateCommand;
import io.dodn.springboot.core.domain.pki.cmp.CmpTransaction;
import io.dodn.springboot.core.domain.pki.cmp.CmpTransactionRepository;
import io.dodn.springboot.core.domain.pki.vo.CmpTransactionId;
import io.dodn.springboot.core.domain.pki.vo.ExtKeyUsageExtension;
import io.dodn.springboot.core.domain.pki.vo.KeyUsageExtension;
import io.dodn.springboot.core.domain.pki.vo.Nonce;
import io.dodn.springboot.core.domain.pki.vo.SanExtension;
import io.dodn.springboot.core.domain.pki.vo.SerialNumber;
import io.dodn.springboot.core.domain.pki.vo.SubjectDN;
import io.dodn.springboot.core.enums.pki.CmpBodyType;
import io.dodn.springboot.core.enums.pki.RevocationReason;
import io.dodn.springboot.core.support.error.CoreException;
import io.dodn.springboot.core.support.error.ErrorType;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.cmp.PKIBody;
import org.bouncycastle.asn1.cmp.PKIMessage;
import org.bouncycastle.asn1.cmp.RevDetails;
import org.bouncycastle.asn1.cmp.RevReqContent;
import org.bouncycastle.asn1.crmf.CertReqMessages;
import org.bouncycastle.asn1.crmf.CertReqMsg;
import org.bouncycastle.asn1.crmf.CertTemplate;
import org.bouncycastle.asn1.pkcs.CertificationRequest;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.springframework.stereotype.Service;

import java.math.BigInteger;
import java.security.PublicKey;
import java.util.Set;

@Service
public class CmpRequestProcessor {

    private final CaRepository caRepository;
    private final CmpTransactionRepository cmpTransactionRepository;
    private final CertificateIssuanceService certIssuanceService;
    private final IssuedCertificateRepository issuedCertificateRepository;
    private final CmpMessageBuilder messageBuilder;
    private final CmpProtectionVerifier protectionVerifier;

    public CmpRequestProcessor(CaRepository caRepository,
            CmpTransactionRepository cmpTransactionRepository,
            CertificateIssuanceService certIssuanceService,
            IssuedCertificateRepository issuedCertificateRepository,
            CmpMessageBuilder messageBuilder,
            CmpProtectionVerifier protectionVerifier) {
        this.caRepository = caRepository;
        this.cmpTransactionRepository = cmpTransactionRepository;
        this.certIssuanceService = certIssuanceService;
        this.issuedCertificateRepository = issuedCertificateRepository;
        this.messageBuilder = messageBuilder;
        this.protectionVerifier = protectionVerifier;
    }

    public byte[] process(byte[] derPkiMessage, String caAlias) {
        PKIMessage pkiMessage;
        try {
            pkiMessage = PKIMessage.getInstance(derPkiMessage);
        } catch (Exception e) {
            throw new CoreException(ErrorType.PKI_CMP_PARSE_ERROR, e.getMessage());
        }

        CertificateAuthority ca = caRepository.findByAlias(CaAlias.of(caAlias))
                .orElseThrow(() -> new CoreException(ErrorType.PKI_CA_NOT_FOUND, caAlias));

        PKIBody body = pkiMessage.getBody();
        int bodyType = body.getType();

        try {
            return switch (bodyType) {
                case PKIBody.TYPE_INIT_REQ -> processIrCr(pkiMessage, ca, true);
                case PKIBody.TYPE_CERT_REQ -> processIrCr(pkiMessage, ca, false);
                case PKIBody.TYPE_P10_CERT_REQ -> processP10Cr(pkiMessage, ca);
                case PKIBody.TYPE_REVOCATION_REQ -> processRr(pkiMessage, ca);
                case PKIBody.TYPE_CERT_CONFIRM -> processCertConf(pkiMessage);
                default -> messageBuilder.buildErrorResponse(pkiMessage, "Unsupported message type: " + bodyType);
            };
        } catch (CoreException e) {
            return messageBuilder.buildErrorResponse(pkiMessage, e.getMessage());
        } catch (Exception e) {
            return messageBuilder.buildErrorResponse(pkiMessage, "Internal processing error");
        }
    }

    private byte[] processIrCr(PKIMessage pkiMessage, CertificateAuthority ca, boolean isIr) {
        CertReqMessages certReqMessages = CertReqMessages.getInstance(pkiMessage.getBody().getContent());
        CertReqMsg certReqMsg = certReqMessages.toCertReqMsgArray()[0];
        CertTemplate template = certReqMsg.getCertReq().getCertTemplate();

        X500Name subject = template.getSubject();
        SubjectDN subjectDN = subject != null ? SubjectDN.parse(subject.toString()) :
                new SubjectDN("Unknown", null, null, null, null, null);

        PublicKey publicKey = extractPublicKey(template);
        CmpTransactionId txId = extractTransactionId(pkiMessage);

        IssueCertificateCommand command = new IssueCertificateCommand(
                subjectDN, publicKey,
                new KeyUsageExtension(Set.of()),
                new ExtKeyUsageExtension(Set.of()),
                new SanExtension(java.util.List.of()),
                txId
        );

        IssuedCertificate cert = certIssuanceService.issueCertificate(command, ca.getId());
        saveTransaction(pkiMessage, CmpBodyType.IR, txId);

        return messageBuilder.buildIpCpResponse(pkiMessage, cert, isIr);
    }

    private byte[] processP10Cr(PKIMessage pkiMessage, CertificateAuthority ca) {
        try {
            CertificationRequest cr = CertificationRequest.getInstance(pkiMessage.getBody().getContent());
            PKCS10CertificationRequest p10 = new PKCS10CertificationRequest(cr);

            SubjectDN subjectDN = SubjectDN.parse(p10.getSubject().toString());
            PublicKey publicKey = org.bouncycastle.jce.provider.BouncyCastleProvider.getPublicKey(
                    p10.getSubjectPublicKeyInfo());
            CmpTransactionId txId = extractTransactionId(pkiMessage);

            IssueCertificateCommand command = new IssueCertificateCommand(
                    subjectDN, publicKey,
                    new KeyUsageExtension(Set.of()),
                    new ExtKeyUsageExtension(Set.of()),
                    new SanExtension(java.util.List.of()),
                    txId
            );

            IssuedCertificate cert = certIssuanceService.issueCertificate(command, ca.getId());
            saveTransaction(pkiMessage, CmpBodyType.P10CR, txId);

            return messageBuilder.buildIpCpResponse(pkiMessage, cert, false);
        } catch (Exception e) {
            throw new IllegalStateException("Failed to process P10CR", e);
        }
    }

    private byte[] processRr(PKIMessage pkiMessage, CertificateAuthority ca) {
        RevReqContent revReqContent = RevReqContent.getInstance(pkiMessage.getBody().getContent());
        RevDetails revDetails = revReqContent.toRevDetailsArray()[0];
        CertTemplate template = revDetails.getCertDetails();

        BigInteger serial = template.getSerialNumber().getValue();
        SerialNumber serialNumber = SerialNumber.of(serial);
        RevocationReason reason = RevocationReason.UNSPECIFIED;
        if (revDetails.getCrlEntryDetails() != null) {
            // Extract reason from CRL entry details if present
        }

        certIssuanceService.revokeCertificate(serialNumber, ca.getId(), reason);

        CmpTransactionId txId = extractTransactionId(pkiMessage);
        saveTransaction(pkiMessage, CmpBodyType.RR, txId);

        return messageBuilder.buildRpResponse(pkiMessage);
    }

    private byte[] processCertConf(PKIMessage pkiMessage) {
        CmpTransactionId txId = extractTransactionId(pkiMessage);
        cmpTransactionRepository.findByTransactionId(txId).ifPresent(tx -> {
            tx.complete();
            cmpTransactionRepository.save(tx);
        });
        return messageBuilder.buildPkiConfResponse(pkiMessage);
    }

    private CmpTransactionId extractTransactionId(PKIMessage pkiMessage) {
        ASN1OctetString txIdOctet = pkiMessage.getHeader().getTransactionID();
        if (txIdOctet != null && txIdOctet.getOctets().length == 16) {
            return new CmpTransactionId(txIdOctet.getOctets());
        }
        return CmpTransactionId.generate();
    }

    private PublicKey extractPublicKey(CertTemplate template) {
        try {
            if (template.getPublicKey() != null) {
                return org.bouncycastle.jce.provider.BouncyCastleProvider.getPublicKey(template.getPublicKey());
            }
            throw new IllegalArgumentException("No public key in certificate template");
        } catch (Exception e) {
            throw new IllegalStateException("Failed to extract public key from template", e);
        }
    }

    private void saveTransaction(PKIMessage pkiMessage, CmpBodyType bodyType, CmpTransactionId txId) {
        ASN1OctetString nonceOctet = pkiMessage.getHeader().getSenderNonce();
        Nonce senderNonce = nonceOctet != null ? Nonce.fromBytes(nonceOctet.getOctets()) : Nonce.generate();
        String sender = pkiMessage.getHeader().getSender() != null ?
                pkiMessage.getHeader().getSender().toString() : "unknown";

        CmpTransaction tx = new CmpTransaction(txId, sender, senderNonce, bodyType);
        tx.waitConfirm();
        cmpTransactionRepository.save(tx);
    }
}
