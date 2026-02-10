package io.dodn.springboot.core.domain.pki.vo;

import java.net.URI;

public record CrlDistributionPoint(String url) {

    public CrlDistributionPoint {
        if (url == null || url.isBlank()) {
            throw new IllegalArgumentException("CRL distribution point URL must not be blank");
        }
    }

    public void validate() {
        try {
            URI uri = URI.create(url);
            String scheme = uri.getScheme();
            if (!"http".equalsIgnoreCase(scheme) && !"https".equalsIgnoreCase(scheme) && !"ldap".equalsIgnoreCase(scheme)) {
                throw new IllegalArgumentException("CRL distribution point must use http, https, or ldap scheme: " + url);
            }
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("Invalid CRL distribution point URL: " + url, e);
        }
    }
}
