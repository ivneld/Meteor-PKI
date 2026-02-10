package io.dodn.springboot.core.domain.pki.ca.service;

import io.dodn.springboot.core.domain.pki.vo.CaId;
import io.dodn.springboot.core.domain.pki.vo.KeyAlgorithm;
import io.dodn.springboot.core.domain.pki.vo.SubjectDN;

public record CreateSubCaCommand(String alias, SubjectDN subjectDN, KeyAlgorithm keyAlgorithm, CaId parentId) {
}
