package io.dodn.springboot.core.domain.pki.crypto;

import io.dodn.springboot.core.domain.pki.ca.CertificateAuthority;
import io.dodn.springboot.core.domain.pki.certificate.IssuedCertificate;
import org.bouncycastle.cert.X509v2CRLBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CRLConverter;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509v2CRLBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.springframework.stereotype.Service;

import java.security.PrivateKey;
import java.security.cert.X509CRL;
import java.util.Date;
import java.util.List;

@Service
public class CrlBuilderService {

    private static final long CRL_VALIDITY_DAYS = 1;

    public byte[] buildCrl(CertificateAuthority ca, List<IssuedCertificate> revokedCerts,
            PrivateKey caPrivateKey) {
        try {
            JcaX509ExtensionUtils extUtils = new JcaX509ExtensionUtils();
            Date thisUpdate = new Date();
            Date nextUpdate = new Date(thisUpdate.getTime() + CRL_VALIDITY_DAYS * 24 * 60 * 60 * 1000L);

            X509v2CRLBuilder crlBuilder = new JcaX509v2CRLBuilder(ca.getCertificate().toX509Certificate(), thisUpdate);
            crlBuilder.setNextUpdate(nextUpdate);
            crlBuilder.addExtension(
                    org.bouncycastle.asn1.x509.Extension.authorityKeyIdentifier,
                    false,
                    extUtils.createAuthorityKeyIdentifier(ca.getCertificate().toX509Certificate()));
            crlBuilder.addExtension(
                    org.bouncycastle.asn1.x509.Extension.cRLNumber,
                    false,
                    new org.bouncycastle.asn1.x509.CRLNumber(
                            java.math.BigInteger.valueOf(System.currentTimeMillis())));

            for (IssuedCertificate cert : revokedCerts) {
                crlBuilder.addCRLEntry(
                        cert.getSerialNumber().value(),
                        Date.from(cert.getRevokedAt()),
                        cert.getRevocationReason().getCode()
                );
            }

            ContentSigner signer = new JcaContentSignerBuilder(ca.getKeyAlgorithm().toSignatureAlgorithm())
                    .setProvider("BC").build(caPrivateKey);
            X509CRL crl = new JcaX509CRLConverter().setProvider("BC").getCRL(crlBuilder.build(signer));
            return crl.getEncoded();
        } catch (Exception e) {
            throw new IllegalStateException("Failed to build CRL", e);
        }
    }
}
