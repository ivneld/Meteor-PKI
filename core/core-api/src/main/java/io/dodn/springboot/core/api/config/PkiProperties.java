package io.dodn.springboot.core.api.config;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.DefaultValue;

@ConfigurationProperties(prefix = "pki")
public record PkiProperties(
        String keyEncryptionSecret,
        DefaultValidityDays defaultValidityDays,
        String crlDistributionBaseUrl
) {
    public record DefaultValidityDays(
            @DefaultValue("7300") int rootCa,
            @DefaultValue("3650") int subCa,
            @DefaultValue("365") int endEntity
    ) {}
}
