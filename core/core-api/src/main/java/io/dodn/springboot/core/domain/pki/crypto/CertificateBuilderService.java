package io.dodn.springboot.core.domain.pki.crypto;

import io.dodn.springboot.core.domain.pki.ca.CertificateAuthority;
import io.dodn.springboot.core.domain.pki.vo.CaChainDepth;
import io.dodn.springboot.core.domain.pki.vo.CertificatePem;
import io.dodn.springboot.core.domain.pki.vo.CertificateValidity;
import io.dodn.springboot.core.domain.pki.vo.CrlDistributionPoint;
import io.dodn.springboot.core.domain.pki.vo.ExtKeyUsageExtension;
import io.dodn.springboot.core.domain.pki.vo.KeyUsageExtension;
import io.dodn.springboot.core.domain.pki.vo.SanExtension;
import io.dodn.springboot.core.domain.pki.vo.SanValue;
import io.dodn.springboot.core.domain.pki.vo.SerialNumber;
import io.dodn.springboot.core.domain.pki.vo.SubjectDN;
import io.dodn.springboot.core.enums.pki.KeyUsageFlag;
import org.bouncycastle.asn1.x509.AccessDescription;
import org.bouncycastle.asn1.x509.AuthorityInformationAccess;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.CRLDistPoint;
import org.bouncycastle.asn1.x509.DistributionPoint;
import org.bouncycastle.asn1.x509.DistributionPointName;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.springframework.stereotype.Service;

import java.math.BigInteger;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.EnumSet;
import java.util.Set;

@Service
public class CertificateBuilderService {

    public CertificatePem buildRootCaCertificate(SubjectDN subjectDN, SerialNumber serialNumber,
            CertificateValidity validity, PublicKey publicKey, PrivateKey privateKey,
            CrlDistributionPoint crlDp, String signatureAlgorithm) {
        try {
            JcaX509ExtensionUtils extUtils = new JcaX509ExtensionUtils();
            X509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
                    subjectDN.toX500Name(),
                    serialNumber.value(),
                    Date.from(validity.notBefore()),
                    Date.from(validity.notAfter()),
                    subjectDN.toX500Name(),
                    publicKey
            );

            builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));
            builder.addExtension(Extension.keyUsage, true,
                    new org.bouncycastle.asn1.x509.KeyUsage(
                            org.bouncycastle.asn1.x509.KeyUsage.keyCertSign |
                            org.bouncycastle.asn1.x509.KeyUsage.cRLSign));
            builder.addExtension(Extension.subjectKeyIdentifier, false, extUtils.createSubjectKeyIdentifier(publicKey));
            builder.addExtension(Extension.authorityKeyIdentifier, false, extUtils.createAuthorityKeyIdentifier(publicKey));
            addCdpExtension(builder, crlDp);

            ContentSigner signer = new JcaContentSignerBuilder(signatureAlgorithm).setProvider("BC").build(privateKey);
            X509Certificate cert = new JcaX509CertificateConverter().setProvider("BC").getCertificate(builder.build(signer));
            return CertificatePem.fromX509(cert);
        } catch (Exception e) {
            throw new IllegalStateException("Failed to build Root CA certificate", e);
        }
    }

    public CertificatePem buildSubCaCertificate(SubjectDN subjectDN, SerialNumber serialNumber,
            CertificateValidity validity, PublicKey publicKey, CaChainDepth chainDepth,
            CertificateAuthority issuer, PrivateKey issuerPrivateKey,
            CrlDistributionPoint crlDp, String aiaUrl) {
        try {
            JcaX509ExtensionUtils extUtils = new JcaX509ExtensionUtils();
            X509Certificate issuerCert = issuer.getCertificate().toX509Certificate();

            X509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
                    issuer.getSubjectDN().toX500Name(),
                    serialNumber.value(),
                    Date.from(validity.notBefore()),
                    Date.from(validity.notAfter()),
                    subjectDN.toX500Name(),
                    publicKey
            );

            int pathLen = chainDepth.isUnlimited() ? Integer.MAX_VALUE : chainDepth.pathLen();
            builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(pathLen));
            builder.addExtension(Extension.keyUsage, true,
                    new org.bouncycastle.asn1.x509.KeyUsage(
                            org.bouncycastle.asn1.x509.KeyUsage.keyCertSign |
                            org.bouncycastle.asn1.x509.KeyUsage.cRLSign));
            builder.addExtension(Extension.subjectKeyIdentifier, false, extUtils.createSubjectKeyIdentifier(publicKey));
            builder.addExtension(Extension.authorityKeyIdentifier, false, extUtils.createAuthorityKeyIdentifier(issuerCert));
            addCdpExtension(builder, crlDp);
            if (aiaUrl != null && !aiaUrl.isBlank()) {
                addAiaExtension(builder, aiaUrl);
            }

            ContentSigner signer = new JcaContentSignerBuilder(issuer.getKeyAlgorithm().toSignatureAlgorithm())
                    .setProvider("BC").build(issuerPrivateKey);
            X509Certificate cert = new JcaX509CertificateConverter().setProvider("BC").getCertificate(builder.build(signer));
            return CertificatePem.fromX509(cert);
        } catch (Exception e) {
            throw new IllegalStateException("Failed to build Sub CA certificate", e);
        }
    }

    public CertificatePem buildEndEntityCertificate(SubjectDN subjectDN, SerialNumber serialNumber,
            CertificateValidity validity, PublicKey publicKey, KeyUsageExtension keyUsage,
            ExtKeyUsageExtension extKeyUsage, SanExtension san, CertificateAuthority issuer,
            PrivateKey issuerPrivateKey, CrlDistributionPoint crlDp, String aiaUrl) {
        try {
            JcaX509ExtensionUtils extUtils = new JcaX509ExtensionUtils();
            X509Certificate issuerCert = issuer.getCertificate().toX509Certificate();

            X509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
                    issuer.getSubjectDN().toX500Name(),
                    serialNumber.value(),
                    Date.from(validity.notBefore()),
                    Date.from(validity.notAfter()),
                    subjectDN.toX500Name(),
                    publicKey
            );

            builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(false));
            if (!keyUsage.flags().isEmpty()) {
                builder.addExtension(Extension.keyUsage, true,
                        new org.bouncycastle.asn1.x509.KeyUsage(keyUsage.toBouncyCastleBits()));
            }
            if (!extKeyUsage.usages().isEmpty()) {
                KeyPurposeId[] oids = extKeyUsage.toOids().toArray(new KeyPurposeId[0]);
                builder.addExtension(Extension.extendedKeyUsage, false,
                        new org.bouncycastle.asn1.x509.ExtendedKeyUsage(oids));
            }
            builder.addExtension(Extension.subjectKeyIdentifier, false, extUtils.createSubjectKeyIdentifier(publicKey));
            builder.addExtension(Extension.authorityKeyIdentifier, false, extUtils.createAuthorityKeyIdentifier(issuerCert));
            addCdpExtension(builder, crlDp);
            if (aiaUrl != null && !aiaUrl.isBlank()) {
                addAiaExtension(builder, aiaUrl);
            }
            if (!san.isEmpty()) {
                addSanExtension(builder, san);
            }

            ContentSigner signer = new JcaContentSignerBuilder(issuer.getKeyAlgorithm().toSignatureAlgorithm())
                    .setProvider("BC").build(issuerPrivateKey);
            X509Certificate cert = new JcaX509CertificateConverter().setProvider("BC").getCertificate(builder.build(signer));
            return CertificatePem.fromX509(cert);
        } catch (Exception e) {
            throw new IllegalStateException("Failed to build end-entity certificate", e);
        }
    }

    private void addCdpExtension(X509v3CertificateBuilder builder, CrlDistributionPoint crlDp) throws Exception {
        if (crlDp == null) return;
        GeneralName gn = new GeneralName(GeneralName.uniformResourceIdentifier, crlDp.url());
        DistributionPointName dpName = new DistributionPointName(new GeneralNames(gn));
        DistributionPoint dp = new DistributionPoint(dpName, null, null);
        builder.addExtension(Extension.cRLDistributionPoints, false, new CRLDistPoint(new DistributionPoint[]{dp}));
    }

    private void addAiaExtension(X509v3CertificateBuilder builder, String aiaUrl) throws Exception {
        GeneralName gn = new GeneralName(GeneralName.uniformResourceIdentifier, aiaUrl);
        AccessDescription ad = new AccessDescription(AccessDescription.id_ad_caIssuers, gn);
        builder.addExtension(Extension.authorityInfoAccess, false, new AuthorityInformationAccess(ad));
    }

    private void addSanExtension(X509v3CertificateBuilder builder, SanExtension san) throws Exception {
        GeneralName[] names = san.values().stream().map(v -> switch (v) {
            case SanValue.DnsName d -> new GeneralName(GeneralName.dNSName, d.value());
            case SanValue.IpAddress ip -> new GeneralName(GeneralName.iPAddress, ip.value());
            case SanValue.EmailAddress e -> new GeneralName(GeneralName.rfc822Name, e.value());
        }).toArray(GeneralName[]::new);
        builder.addExtension(Extension.subjectAlternativeName, false, new GeneralNames(names));
    }
}
