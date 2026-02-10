package io.dodn.springboot.core.api.controller.v1.request;

import io.dodn.springboot.core.domain.pki.ca.service.CreateSubCaCommand;
import io.dodn.springboot.core.domain.pki.vo.CaId;
import io.dodn.springboot.core.domain.pki.vo.KeyAlgorithm;
import io.dodn.springboot.core.domain.pki.vo.SubjectDN;
import io.dodn.springboot.core.enums.pki.KeyAlgorithmType;

public record CreateSubCaRequest(
        String alias,
        String cn,
        String o,
        String ou,
        String c,
        String st,
        String l,
        KeyAlgorithmType keyAlgorithmType,
        Long parentId
) {
    public CreateSubCaCommand toCommand() {
        return new CreateSubCaCommand(
                alias,
                new SubjectDN(cn, o, ou, c, st, l),
                new KeyAlgorithm(keyAlgorithmType != null ? keyAlgorithmType : KeyAlgorithmType.RSA_2048),
                CaId.of(parentId)
        );
    }
}
