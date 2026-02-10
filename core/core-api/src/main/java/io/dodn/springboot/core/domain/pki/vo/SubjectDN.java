package io.dodn.springboot.core.domain.pki.vo;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;

public record SubjectDN(String cn, String o, String ou, String c, String st, String l) {

    public SubjectDN {
        if (cn == null || cn.isBlank()) {
            throw new IllegalArgumentException("CN (Common Name) must not be blank");
        }
    }

    public X500Name toX500Name() {
        X500NameBuilder builder = new X500NameBuilder(BCStyle.INSTANCE);
        if (c != null && !c.isBlank()) builder.addRDN(BCStyle.C, c);
        if (st != null && !st.isBlank()) builder.addRDN(BCStyle.ST, st);
        if (l != null && !l.isBlank()) builder.addRDN(BCStyle.L, l);
        if (o != null && !o.isBlank()) builder.addRDN(BCStyle.O, o);
        if (ou != null && !ou.isBlank()) builder.addRDN(BCStyle.OU, ou);
        builder.addRDN(BCStyle.CN, cn);
        return builder.build();
    }

    public String toRfc2253() {
        StringBuilder sb = new StringBuilder();
        sb.append("CN=").append(cn);
        if (ou != null && !ou.isBlank()) sb.append(",OU=").append(ou);
        if (o != null && !o.isBlank()) sb.append(",O=").append(o);
        if (l != null && !l.isBlank()) sb.append(",L=").append(l);
        if (st != null && !st.isBlank()) sb.append(",ST=").append(st);
        if (c != null && !c.isBlank()) sb.append(",C=").append(c);
        return sb.toString();
    }

    public static SubjectDN parse(String rfc2253) {
        String cnVal = null, oVal = null, ouVal = null, cVal = null, stVal = null, lVal = null;
        for (String part : rfc2253.split(",")) {
            String[] kv = part.trim().split("=", 2);
            if (kv.length != 2) continue;
            String key = kv[0].trim().toUpperCase();
            String val = kv[1].trim();
            switch (key) {
                case "CN" -> cnVal = val;
                case "O" -> oVal = val;
                case "OU" -> ouVal = val;
                case "C" -> cVal = val;
                case "ST" -> stVal = val;
                case "L" -> lVal = val;
            }
        }
        return new SubjectDN(cnVal, oVal, ouVal, cVal, stVal, lVal);
    }
}
