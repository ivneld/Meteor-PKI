package io.dodn.springboot.storage.db.core.pki;

import io.dodn.springboot.core.enums.pki.CmpBodyType;
import io.dodn.springboot.core.enums.pki.CmpTransactionStatus;
import io.dodn.springboot.storage.db.core.BaseEntity;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.Table;

@Entity
@Table(name = "cmp_transaction")
public class CmpTransactionJpaEntity extends BaseEntity {

    @Column(nullable = false, unique = true, length = 64)
    private String transactionIdHex;

    @Column(nullable = false, length = 500)
    private String sender;

    @Column(nullable = false, length = 64)
    private String senderNonceHex;

    @Column(length = 64)
    private String recipientNonceHex;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 20)
    private CmpBodyType requestType;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 20)
    private CmpTransactionStatus status;

    @Column(length = 2000)
    private String errorInfo;

    protected CmpTransactionJpaEntity() {}

    public CmpTransactionJpaEntity(String transactionIdHex, String sender, String senderNonceHex,
            String recipientNonceHex, CmpBodyType requestType, CmpTransactionStatus status,
            String errorInfo) {
        this.transactionIdHex = transactionIdHex;
        this.sender = sender;
        this.senderNonceHex = senderNonceHex;
        this.recipientNonceHex = recipientNonceHex;
        this.requestType = requestType;
        this.status = status;
        this.errorInfo = errorInfo;
    }

    public String getTransactionIdHex() { return transactionIdHex; }
    public String getSender() { return sender; }
    public String getSenderNonceHex() { return senderNonceHex; }
    public String getRecipientNonceHex() { return recipientNonceHex; }
    public void setRecipientNonceHex(String hex) { this.recipientNonceHex = hex; }
    public CmpBodyType getRequestType() { return requestType; }
    public CmpTransactionStatus getStatus() { return status; }
    public void setStatus(CmpTransactionStatus status) { this.status = status; }
    public String getErrorInfo() { return errorInfo; }
    public void setErrorInfo(String errorInfo) { this.errorInfo = errorInfo; }
}
