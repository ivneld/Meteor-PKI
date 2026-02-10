package io.dodn.springboot.core.domain.pki.ca;

public record CaAlias(String value) {

    public CaAlias {
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException("CaAlias must not be blank");
        }
        if (!value.matches("[a-z0-9\\-]+")) {
            throw new IllegalArgumentException("CaAlias must contain only lowercase letters, digits and hyphens: " + value);
        }
    }

    public static CaAlias of(String value) {
        return new CaAlias(value);
    }
}
