package io.dodn.springboot.core.domain.pki.vo;

import io.dodn.springboot.core.enums.pki.KeyUsageFlag;
import org.bouncycastle.asn1.x509.KeyUsage;

import java.util.Set;

public record KeyUsageExtension(Set<KeyUsageFlag> flags) {

    public KeyUsageExtension {
        flags = flags != null ? Set.copyOf(flags) : Set.of();
    }

    public int toBouncyCastleBits() {
        int bits = 0;
        for (KeyUsageFlag flag : flags) {
            bits |= switch (flag) {
                case DIGITAL_SIGNATURE -> KeyUsage.digitalSignature;
                case KEY_CERT_SIGN -> KeyUsage.keyCertSign;
                case CRL_SIGN -> KeyUsage.cRLSign;
                case KEY_ENCIPHERMENT -> KeyUsage.keyEncipherment;
                case DATA_ENCIPHERMENT -> KeyUsage.dataEncipherment;
                case KEY_AGREEMENT -> KeyUsage.keyAgreement;
            };
        }
        return bits;
    }
}
