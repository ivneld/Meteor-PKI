package io.dodn.springboot.core.domain.pki.vo;

import io.dodn.springboot.core.enums.pki.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.KeyPurposeId;

import java.util.List;
import java.util.Set;

public record ExtKeyUsageExtension(Set<ExtendedKeyUsage> usages) {

    public ExtKeyUsageExtension {
        usages = usages != null ? Set.copyOf(usages) : Set.of();
    }

    public List<KeyPurposeId> toOids() {
        return usages.stream().map(u -> switch (u) {
            case SERVER_AUTH -> KeyPurposeId.id_kp_serverAuth;
            case CLIENT_AUTH -> KeyPurposeId.id_kp_clientAuth;
            case CODE_SIGNING -> KeyPurposeId.id_kp_codeSigning;
            case EMAIL_PROTECTION -> KeyPurposeId.id_kp_emailProtection;
        }).toList();
    }
}
