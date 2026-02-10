package io.dodn.springboot.core.domain.pki.ca;

import io.dodn.springboot.core.domain.pki.vo.CaId;

import java.util.List;
import java.util.Optional;

public interface CaRepository {

    Optional<CertificateAuthority> findByAlias(CaAlias alias);

    Optional<CertificateAuthority> findById(CaId id);

    List<CertificateAuthority> findAll();

    List<CertificateAuthority> findByParentId(CaId parentId);

    CertificateAuthority save(CertificateAuthority ca);

    boolean existsByAlias(CaAlias alias);
}
