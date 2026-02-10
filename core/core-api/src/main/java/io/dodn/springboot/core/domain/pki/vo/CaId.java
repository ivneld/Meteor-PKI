package io.dodn.springboot.core.domain.pki.vo;

public record CaId(Long value) {

    public CaId {
        if (value == null) {
            throw new IllegalArgumentException("CaId value must not be null");
        }
    }

    public static CaId of(Long value) {
        return new CaId(value);
    }
}
