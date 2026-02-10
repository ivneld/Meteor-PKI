package io.dodn.springboot.core.domain.pki.vo;

public record CaChainDepth(int pathLen) {

    private static final int UNLIMITED = -1;

    public CaChainDepth {
        if (pathLen < UNLIMITED) {
            throw new IllegalArgumentException("pathLen must be >= -1, got: " + pathLen);
        }
    }

    public boolean isUnlimited() {
        return pathLen == UNLIMITED;
    }

    public static CaChainDepth unlimited() {
        return new CaChainDepth(UNLIMITED);
    }

    public static CaChainDepth of(int n) {
        return new CaChainDepth(n);
    }
}
