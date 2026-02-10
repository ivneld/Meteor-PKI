package io.dodn.springboot.core.domain.pki.cmp;

import io.dodn.springboot.core.domain.pki.vo.CmpTransactionId;
import io.dodn.springboot.core.domain.pki.vo.Nonce;
import io.dodn.springboot.core.enums.pki.CmpBodyType;
import io.dodn.springboot.core.enums.pki.CmpTransactionStatus;

public class CmpTransaction {

    private CmpTransactionId transactionId;
    private String sender;
    private Nonce senderNonce;
    private Nonce recipientNonce;
    private CmpBodyType requestType;
    private CmpTransactionStatus status;
    private String errorInfo;

    public CmpTransaction(CmpTransactionId transactionId, String sender, Nonce senderNonce,
            CmpBodyType requestType) {
        this.transactionId = transactionId;
        this.sender = sender;
        this.senderNonce = senderNonce;
        this.requestType = requestType;
        this.status = CmpTransactionStatus.PENDING;
    }

    public CmpTransaction(CmpTransactionId transactionId, String sender, Nonce senderNonce,
            Nonce recipientNonce, CmpBodyType requestType, CmpTransactionStatus status,
            String errorInfo) {
        this.transactionId = transactionId;
        this.sender = sender;
        this.senderNonce = senderNonce;
        this.recipientNonce = recipientNonce;
        this.requestType = requestType;
        this.status = status;
        this.errorInfo = errorInfo;
    }

    public void waitConfirm() {
        this.status = CmpTransactionStatus.WAITING_CONFIRM;
    }

    public void complete() {
        this.status = CmpTransactionStatus.COMPLETED;
    }

    public void fail(String reason) {
        this.status = CmpTransactionStatus.FAILED;
        this.errorInfo = reason;
    }

    public boolean isWaitingConfirm() {
        return status == CmpTransactionStatus.WAITING_CONFIRM;
    }

    public void setRecipientNonce(Nonce recipientNonce) {
        this.recipientNonce = recipientNonce;
    }

    public CmpTransactionId getTransactionId() { return transactionId; }
    public String getSender() { return sender; }
    public Nonce getSenderNonce() { return senderNonce; }
    public Nonce getRecipientNonce() { return recipientNonce; }
    public CmpBodyType getRequestType() { return requestType; }
    public CmpTransactionStatus getStatus() { return status; }
    public String getErrorInfo() { return errorInfo; }
}
