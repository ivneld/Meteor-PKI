package io.dodn.springboot.core.domain.pki.certificate.service;

import io.dodn.springboot.core.domain.pki.vo.CmpTransactionId;
import io.dodn.springboot.core.domain.pki.vo.ExtKeyUsageExtension;
import io.dodn.springboot.core.domain.pki.vo.KeyUsageExtension;
import io.dodn.springboot.core.domain.pki.vo.SanExtension;
import io.dodn.springboot.core.domain.pki.vo.SubjectDN;

import java.security.PublicKey;

public record IssueCertificateCommand(
        SubjectDN subjectDN,
        PublicKey publicKey,
        KeyUsageExtension keyUsage,
        ExtKeyUsageExtension extKeyUsage,
        SanExtension san,
        CmpTransactionId cmpTransactionId
) {
}
