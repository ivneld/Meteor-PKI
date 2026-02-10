package io.dodn.springboot.core.domain.pki.vo;

import java.util.List;

public record SanExtension(List<SanValue> values) {

    public SanExtension {
        values = values != null ? List.copyOf(values) : List.of();
    }

    public boolean isEmpty() {
        return values.isEmpty();
    }
}
