package io.dodn.springboot.core.support.error;

import org.springframework.boot.logging.LogLevel;
import org.springframework.http.HttpStatus;

public enum ErrorType {

    DEFAULT_ERROR(HttpStatus.INTERNAL_SERVER_ERROR, ErrorCode.E500, "An unexpected error has occurred.",
            LogLevel.ERROR),

    PKI_CA_NOT_FOUND(HttpStatus.NOT_FOUND, ErrorCode.E404, "CA not found.", LogLevel.WARN),
    PKI_CA_ALIAS_DUPLICATE(HttpStatus.CONFLICT, ErrorCode.E409, "CA alias already exists.", LogLevel.WARN),
    PKI_CA_NOT_ACTIVE(HttpStatus.UNPROCESSABLE_ENTITY, ErrorCode.E422, "CA is not active.", LogLevel.WARN),
    PKI_CERT_NOT_FOUND(HttpStatus.NOT_FOUND, ErrorCode.E404, "Certificate not found.", LogLevel.WARN),
    PKI_CERT_ALREADY_REVOKED(HttpStatus.CONFLICT, ErrorCode.E409, "Certificate is already revoked.", LogLevel.WARN),
    PKI_CMP_PARSE_ERROR(HttpStatus.BAD_REQUEST, ErrorCode.E400, "Failed to parse CMP message.", LogLevel.WARN);

    private final HttpStatus status;

    private final ErrorCode code;

    private final String message;

    private final LogLevel logLevel;

    ErrorType(HttpStatus status, ErrorCode code, String message, LogLevel logLevel) {

        this.status = status;
        this.code = code;
        this.message = message;
        this.logLevel = logLevel;
    }

    public HttpStatus getStatus() {
        return status;
    }

    public ErrorCode getCode() {
        return code;
    }

    public String getMessage() {
        return message;
    }

    public LogLevel getLogLevel() {
        return logLevel;
    }

}
