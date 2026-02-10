package io.dodn.springboot.core.enums.pki;

public enum RevocationReason {
    UNSPECIFIED(0),
    KEY_COMPROMISE(1),
    CA_COMPROMISE(2),
    AFFILIATION_CHANGED(3),
    SUPERSEDED(4),
    CESSATION_OF_OPERATION(5),
    CERTIFICATE_HOLD(6),
    PRIVILEGE_WITHDRAWN(9);

    private final int code;

    RevocationReason(int code) {
        this.code = code;
    }

    public int getCode() {
        return code;
    }

    public static RevocationReason fromCode(int code) {
        for (RevocationReason reason : values()) {
            if (reason.code == code) {
                return reason;
            }
        }
        throw new IllegalArgumentException("Unknown revocation reason code: " + code);
    }
}
