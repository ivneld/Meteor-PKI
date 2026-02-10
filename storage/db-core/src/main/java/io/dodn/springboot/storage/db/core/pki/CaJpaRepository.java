package io.dodn.springboot.storage.db.core.pki;

import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.Optional;

public interface CaJpaRepository extends JpaRepository<CaJpaEntity, Long> {

    Optional<CaJpaEntity> findByAlias(String alias);

    List<CaJpaEntity> findByParentId(Long parentId);

    boolean existsByAlias(String alias);
}
