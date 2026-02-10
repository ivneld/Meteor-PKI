package io.dodn.springboot.core.domain.pki.ca.adapter;

import io.dodn.springboot.core.domain.pki.ca.CaAlias;
import io.dodn.springboot.core.domain.pki.ca.CaRepository;
import io.dodn.springboot.core.domain.pki.ca.CertificateAuthority;
import io.dodn.springboot.core.domain.pki.vo.CaChainDepth;
import io.dodn.springboot.core.domain.pki.vo.CaId;
import io.dodn.springboot.core.domain.pki.vo.CertificatePem;
import io.dodn.springboot.core.domain.pki.vo.CertificateValidity;
import io.dodn.springboot.core.domain.pki.vo.CrlDistributionPoint;
import io.dodn.springboot.core.domain.pki.vo.EncryptedPrivateKey;
import io.dodn.springboot.core.domain.pki.vo.KeyAlgorithm;
import io.dodn.springboot.core.domain.pki.vo.SerialNumber;
import io.dodn.springboot.core.domain.pki.vo.SubjectDN;
import io.dodn.springboot.storage.db.core.pki.CaJpaEntity;
import io.dodn.springboot.storage.db.core.pki.CaJpaRepository;
import org.springframework.stereotype.Repository;

import java.math.BigInteger;
import java.util.List;
import java.util.Optional;

@Repository
public class CaRepositoryAdapter implements CaRepository {

    private final CaJpaRepository jpaRepository;

    public CaRepositoryAdapter(CaJpaRepository jpaRepository) {
        this.jpaRepository = jpaRepository;
    }

    @Override
    public Optional<CertificateAuthority> findByAlias(CaAlias alias) {
        return jpaRepository.findByAlias(alias.value()).map(this::toDomain);
    }

    @Override
    public Optional<CertificateAuthority> findById(CaId id) {
        return jpaRepository.findById(id.value()).map(this::toDomain);
    }

    @Override
    public List<CertificateAuthority> findAll() {
        return jpaRepository.findAll().stream().map(this::toDomain).toList();
    }

    @Override
    public List<CertificateAuthority> findByParentId(CaId parentId) {
        return jpaRepository.findByParentId(parentId.value()).stream().map(this::toDomain).toList();
    }

    @Override
    public CertificateAuthority save(CertificateAuthority ca) {
        CaJpaEntity entity = toEntityForSave(ca);
        CaJpaEntity saved = jpaRepository.save(entity);
        return toDomain(saved);
    }

    @Override
    public boolean existsByAlias(CaAlias alias) {
        return jpaRepository.existsByAlias(alias.value());
    }

    private CertificateAuthority toDomain(CaJpaEntity e) {
        CertificatePem certPem = e.getCertificatePem() != null ? new CertificatePem(e.getCertificatePem()) : null;
        CrlDistributionPoint crlDp = e.getCrlDistributionPointUrl() != null ?
                new CrlDistributionPoint(e.getCrlDistributionPointUrl()) : null;

        return new CertificateAuthority(
                CaId.of(e.getId()),
                CaAlias.of(e.getAlias()),
                new SubjectDN(e.getSubjectDnCn(), e.getSubjectDnO(), e.getSubjectDnOu(),
                        e.getSubjectDnC(), e.getSubjectDnSt(), e.getSubjectDnL()),
                e.getType(),
                new KeyAlgorithm(e.getKeyAlgorithmType()),
                e.getParentId() != null ? CaId.of(e.getParentId()) : null,
                EncryptedPrivateKey.fromBase64(e.getEncryptedPrivateKeyBase64()),
                certPem,
                SerialNumber.of(new BigInteger(e.getSerialNumberHex(), 16)),
                new CertificateValidity(e.getNotBefore(), e.getNotAfter()),
                e.getStatus(),
                crlDp,
                new CaChainDepth(e.getChainDepthPathLen())
        );
    }

    private CaJpaEntity toEntityForSave(CertificateAuthority ca) {
        if (ca.getId() != null) {
            return jpaRepository.findById(ca.getId().value()).map(existing -> {
                existing.setCertificatePem(ca.getCertificate() != null ? ca.getCertificate().pem() : null);
                existing.setStatus(ca.getStatus());
                return existing;
            }).orElseGet(() -> newEntity(ca));
        }
        return newEntity(ca);
    }

    private CaJpaEntity newEntity(CertificateAuthority ca) {
        return new CaJpaEntity(
                ca.getAlias().value(),
                ca.getSubjectDN().cn(),
                ca.getSubjectDN().o(),
                ca.getSubjectDN().ou(),
                ca.getSubjectDN().c(),
                ca.getSubjectDN().st(),
                ca.getSubjectDN().l(),
                ca.getType(),
                ca.getKeyAlgorithm().type(),
                ca.getParentId() != null ? ca.getParentId().value() : null,
                ca.getPrivateKey().toBase64(),
                ca.getCertificate() != null ? ca.getCertificate().pem() : null,
                ca.getSerialNumber().toHex(),
                ca.getValidity().notBefore(),
                ca.getValidity().notAfter(),
                ca.getStatus(),
                ca.getCrlDp() != null ? ca.getCrlDp().url() : null,
                ca.getChainDepth().pathLen()
        );
    }
}
