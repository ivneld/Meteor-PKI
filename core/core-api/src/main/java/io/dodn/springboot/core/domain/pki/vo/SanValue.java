package io.dodn.springboot.core.domain.pki.vo;

public sealed interface SanValue permits SanValue.DnsName, SanValue.IpAddress, SanValue.EmailAddress {

    record DnsName(String value) implements SanValue {
        public DnsName {
            if (value == null || value.isBlank()) {
                throw new IllegalArgumentException("DNS name must not be blank");
            }
        }
    }

    record IpAddress(String value) implements SanValue {
        public IpAddress {
            if (value == null || value.isBlank()) {
                throw new IllegalArgumentException("IP address must not be blank");
            }
        }
    }

    record EmailAddress(String value) implements SanValue {
        public EmailAddress {
            if (value == null || value.isBlank()) {
                throw new IllegalArgumentException("Email address must not be blank");
            }
        }
    }
}
