package io.dodn.springboot.core.domain.pki.vo;

import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;
import org.bouncycastle.util.io.pem.PemWriter;

import java.io.ByteArrayInputStream;
import java.io.StringReader;
import java.io.StringWriter;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Base64;

public record CertificatePem(String pem) {

    public CertificatePem {
        if (pem == null || pem.isBlank()) {
            throw new IllegalArgumentException("PEM string must not be blank");
        }
    }

    public X509Certificate toX509Certificate() {
        try {
            PemReader reader = new PemReader(new StringReader(pem));
            PemObject pemObject = reader.readPemObject();
            byte[] der = pemObject.getContent();
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            return (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(der));
        } catch (Exception e) {
            throw new IllegalStateException("Failed to parse PEM certificate", e);
        }
    }

    public byte[] toDer() {
        try {
            PemReader reader = new PemReader(new StringReader(pem));
            PemObject pemObject = reader.readPemObject();
            return pemObject.getContent();
        } catch (Exception e) {
            throw new IllegalStateException("Failed to extract DER from PEM", e);
        }
    }

    public static CertificatePem fromDer(byte[] der) {
        try {
            StringWriter sw = new StringWriter();
            PemWriter pw = new PemWriter(sw);
            pw.writeObject(new PemObject("CERTIFICATE", der));
            pw.close();
            return new CertificatePem(sw.toString());
        } catch (Exception e) {
            throw new IllegalStateException("Failed to encode DER to PEM", e);
        }
    }

    public static CertificatePem fromX509(X509Certificate cert) {
        try {
            return fromDer(cert.getEncoded());
        } catch (Exception e) {
            throw new IllegalStateException("Failed to encode X509Certificate to PEM", e);
        }
    }
}
