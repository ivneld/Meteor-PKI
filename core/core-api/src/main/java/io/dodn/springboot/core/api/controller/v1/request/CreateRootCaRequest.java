package io.dodn.springboot.core.api.controller.v1.request;

import io.dodn.springboot.core.domain.pki.ca.service.CreateRootCaCommand;
import io.dodn.springboot.core.domain.pki.vo.KeyAlgorithm;
import io.dodn.springboot.core.domain.pki.vo.SubjectDN;
import io.dodn.springboot.core.enums.pki.KeyAlgorithmType;

public record CreateRootCaRequest(
        String alias,
        String cn,
        String o,
        String ou,
        String c,
        String st,
        String l,
        KeyAlgorithmType keyAlgorithmType
) {
    public CreateRootCaCommand toCommand() {
        return new CreateRootCaCommand(
                alias,
                new SubjectDN(cn, o, ou, c, st, l),
                new KeyAlgorithm(keyAlgorithmType != null ? keyAlgorithmType : KeyAlgorithmType.RSA_2048)
        );
    }
}
