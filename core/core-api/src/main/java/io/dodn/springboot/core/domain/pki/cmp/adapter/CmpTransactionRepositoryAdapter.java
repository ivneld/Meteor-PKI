package io.dodn.springboot.core.domain.pki.cmp.adapter;

import io.dodn.springboot.core.domain.pki.cmp.CmpTransaction;
import io.dodn.springboot.core.domain.pki.cmp.CmpTransactionRepository;
import io.dodn.springboot.core.domain.pki.vo.CmpTransactionId;
import io.dodn.springboot.core.domain.pki.vo.Nonce;
import io.dodn.springboot.storage.db.core.pki.CmpTransactionJpaEntity;
import io.dodn.springboot.storage.db.core.pki.CmpTransactionJpaRepository;
import org.springframework.stereotype.Repository;

import java.util.HexFormat;
import java.util.Optional;

@Repository
public class CmpTransactionRepositoryAdapter implements CmpTransactionRepository {

    private final CmpTransactionJpaRepository jpaRepository;

    public CmpTransactionRepositoryAdapter(CmpTransactionJpaRepository jpaRepository) {
        this.jpaRepository = jpaRepository;
    }

    @Override
    public Optional<CmpTransaction> findByTransactionId(CmpTransactionId id) {
        return jpaRepository.findByTransactionIdHex(id.toHex()).map(this::toDomain);
    }

    @Override
    public CmpTransaction save(CmpTransaction tx) {
        CmpTransactionJpaEntity entity = jpaRepository.findByTransactionIdHex(tx.getTransactionId().toHex())
                .map(existing -> {
                    existing.setStatus(tx.getStatus());
                    existing.setErrorInfo(tx.getErrorInfo());
                    if (tx.getRecipientNonce() != null) {
                        existing.setRecipientNonceHex(tx.getRecipientNonce().toHex());
                    }
                    return existing;
                })
                .orElseGet(() -> toEntity(tx));
        CmpTransactionJpaEntity saved = jpaRepository.save(entity);
        return toDomain(saved);
    }

    private CmpTransaction toDomain(CmpTransactionJpaEntity e) {
        CmpTransactionId txId = CmpTransactionId.fromHex(e.getTransactionIdHex());
        Nonce senderNonce = Nonce.fromBytes(HexFormat.of().parseHex(e.getSenderNonceHex()));
        Nonce recipientNonce = e.getRecipientNonceHex() != null ?
                Nonce.fromBytes(HexFormat.of().parseHex(e.getRecipientNonceHex())) : null;

        return new CmpTransaction(txId, e.getSender(), senderNonce, recipientNonce,
                e.getRequestType(), e.getStatus(), e.getErrorInfo());
    }

    private CmpTransactionJpaEntity toEntity(CmpTransaction tx) {
        String recipientNonceHex = tx.getRecipientNonce() != null ? tx.getRecipientNonce().toHex() : null;
        return new CmpTransactionJpaEntity(
                tx.getTransactionId().toHex(),
                tx.getSender(),
                tx.getSenderNonce().toHex(),
                recipientNonceHex,
                tx.getRequestType(),
                tx.getStatus(),
                tx.getErrorInfo()
        );
    }
}
