package io.dodn.springboot.core.domain.pki.cmp;

import io.dodn.springboot.core.domain.pki.vo.CmpTransactionId;

import java.util.Optional;

public interface CmpTransactionRepository {

    Optional<CmpTransaction> findByTransactionId(CmpTransactionId id);

    CmpTransaction save(CmpTransaction tx);
}
