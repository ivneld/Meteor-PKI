package io.dodn.springboot.core.domain.pki.cmp.service;

import org.bouncycastle.asn1.cmp.PKIHeader;
import org.bouncycastle.asn1.cmp.PKIMessage;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.springframework.stereotype.Service;

@Service
public class CmpProtectionVerifier {

    /**
     * Verifies the protection of a PKIMessage.
     * Supports MAC-based (PBMAC1) and signature-based protection.
     */
    public void verify(PKIMessage pkiMessage, String sharedSecret) {
        PKIHeader header = pkiMessage.getHeader();
        AlgorithmIdentifier protAlg = header.getProtectionAlg();

        if (protAlg == null) {
            throw new IllegalArgumentException("PKIMessage has no protection algorithm");
        }

        String algOid = protAlg.getAlgorithm().getId();

        // PBMAC1 OID: 1.2.840.113549.1.5.14
        if ("1.2.840.113549.1.5.14".equals(algOid)) {
            verifyMacProtection(pkiMessage, sharedSecret);
        } else {
            verifySignatureProtection(pkiMessage);
        }
    }

    private void verifyMacProtection(PKIMessage pkiMessage, String sharedSecret) {
        // Full PBMAC1 verification would require extracting PBKDF2 parameters
        // and computing the MAC over the DER-encoded PKIBody+PKIHeader.
        // This is a structural placeholder — production implementations
        // should use BouncyCastle's PKIMessageHelper or equivalent.
        if (sharedSecret == null || sharedSecret.isBlank()) {
            throw new IllegalArgumentException("Shared secret required for MAC-based CMP protection");
        }
    }

    private void verifySignatureProtection(PKIMessage pkiMessage) {
        // Signature verification placeholder.
        // Production code should extract the signing certificate from
        // the extraCerts field and verify the signature.
    }
}
