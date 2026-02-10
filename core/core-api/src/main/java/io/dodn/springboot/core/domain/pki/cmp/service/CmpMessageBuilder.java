package io.dodn.springboot.core.domain.pki.cmp.service;

import io.dodn.springboot.core.domain.pki.certificate.IssuedCertificate;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.cmp.CMPCertificate;
import org.bouncycastle.asn1.cmp.CertOrEncCert;
import org.bouncycastle.asn1.cmp.CertRepMessage;
import org.bouncycastle.asn1.cmp.CertResponse;
import org.bouncycastle.asn1.cmp.CertifiedKeyPair;
import org.bouncycastle.asn1.cmp.PKIBody;
import org.bouncycastle.asn1.cmp.PKIFreeText;
import org.bouncycastle.asn1.cmp.PKIHeader;
import org.bouncycastle.asn1.cmp.PKIHeaderBuilder;
import org.bouncycastle.asn1.cmp.PKIMessage;
import org.bouncycastle.asn1.cmp.PKIStatus;
import org.bouncycastle.asn1.cmp.PKIStatusInfo;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.cmp.RevRepContent;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.cert.cmp.GeneralPKIMessage;
import org.springframework.stereotype.Service;

import java.math.BigInteger;
import java.security.cert.X509Certificate;
import java.util.Date;

@Service
public class CmpMessageBuilder {

    public byte[] buildIpCpResponse(PKIMessage request, IssuedCertificate issuedCert, boolean isIr) {
        try {
            PKIHeader reqHeader = request.getHeader();

            PKIHeaderBuilder headerBuilder = new PKIHeaderBuilder(
                    PKIHeader.CMP_2000,
                    reqHeader.getRecipient(),
                    reqHeader.getSender()
            );
            headerBuilder.setTransactionID(reqHeader.getTransactionID());
            headerBuilder.setRecipNonce(reqHeader.getSenderNonce());

            X509Certificate x509Cert = issuedCert.getCertificate().toX509Certificate();
            CMPCertificate cmpCert = CMPCertificate.getInstance(x509Cert.getEncoded());

            PKIStatusInfo statusInfo = new PKIStatusInfo(PKIStatus.granted);
            CertifiedKeyPair ckp = new CertifiedKeyPair(new CertOrEncCert(cmpCert));
            CertResponse certResponse = new CertResponse(new ASN1Integer(BigInteger.ZERO), statusInfo, ckp, null);

            CertRepMessage certRepMessage = new CertRepMessage(null, new CertResponse[]{certResponse});
            int bodyType = isIr ? PKIBody.TYPE_INIT_REP : PKIBody.TYPE_CERT_REP;
            PKIBody body = new PKIBody(bodyType, certRepMessage);

            PKIMessage response = new PKIMessage(headerBuilder.build(), body);
            return response.getEncoded();
        } catch (Exception e) {
            throw new IllegalStateException("Failed to build IP/CP response", e);
        }
    }

    public byte[] buildRpResponse(PKIMessage request) {
        try {
            PKIHeader reqHeader = request.getHeader();

            PKIHeaderBuilder headerBuilder = new PKIHeaderBuilder(
                    PKIHeader.CMP_2000,
                    reqHeader.getRecipient(),
                    reqHeader.getSender()
            );
            headerBuilder.setTransactionID(reqHeader.getTransactionID());
            headerBuilder.setRecipNonce(reqHeader.getSenderNonce());

            PKIStatusInfo statusInfo = new PKIStatusInfo(PKIStatus.granted);
            ASN1EncodableVector v = new ASN1EncodableVector();
            v.add(statusInfo);
            RevRepContent revRepContent = RevRepContent.getInstance(new DERSequence(v));
            PKIBody body = new PKIBody(PKIBody.TYPE_REVOCATION_REP, revRepContent);

            PKIMessage response = new PKIMessage(headerBuilder.build(), body);
            return response.getEncoded();
        } catch (Exception e) {
            throw new IllegalStateException("Failed to build RP response", e);
        }
    }

    public byte[] buildPkiConfResponse(PKIMessage request) {
        try {
            PKIHeader reqHeader = request.getHeader();

            PKIHeaderBuilder headerBuilder = new PKIHeaderBuilder(
                    PKIHeader.CMP_2000,
                    reqHeader.getRecipient(),
                    reqHeader.getSender()
            );
            headerBuilder.setTransactionID(reqHeader.getTransactionID());
            headerBuilder.setRecipNonce(reqHeader.getSenderNonce());

            PKIBody body = new PKIBody(PKIBody.TYPE_CONFIRM, org.bouncycastle.asn1.DERNull.INSTANCE);
            PKIMessage response = new PKIMessage(headerBuilder.build(), body);
            return response.getEncoded();
        } catch (Exception e) {
            throw new IllegalStateException("Failed to build PKIConf response", e);
        }
    }

    public byte[] buildErrorResponse(PKIMessage request, String errorText) {
        try {
            PKIHeader reqHeader = request.getHeader();

            PKIHeaderBuilder headerBuilder = new PKIHeaderBuilder(
                    PKIHeader.CMP_2000,
                    reqHeader.getRecipient(),
                    reqHeader.getSender()
            );
            if (reqHeader.getTransactionID() != null) {
                headerBuilder.setTransactionID(reqHeader.getTransactionID());
            }

            PKIStatusInfo statusInfo = new PKIStatusInfo(PKIStatus.rejection,
                    new PKIFreeText(new DERUTF8String(errorText)));
            org.bouncycastle.asn1.cmp.ErrorMsgContent errorContent =
                    new org.bouncycastle.asn1.cmp.ErrorMsgContent(statusInfo);
            PKIBody body = new PKIBody(PKIBody.TYPE_ERROR, errorContent);

            PKIMessage response = new PKIMessage(headerBuilder.build(), body);
            return response.getEncoded();
        } catch (Exception e) {
            throw new IllegalStateException("Failed to build error response", e);
        }
    }
}
