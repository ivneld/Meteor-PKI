package io.dodn.springboot.storage.db.core.pki;

import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface CmpTransactionJpaRepository extends JpaRepository<CmpTransactionJpaEntity, Long> {

    Optional<CmpTransactionJpaEntity> findByTransactionIdHex(String transactionIdHex);
}
