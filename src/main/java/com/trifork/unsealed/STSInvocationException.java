package com.trifork.unsealed;

public class STSInvocationException extends Exception {
    private String faultCode;
    private String faultString;

    public STSInvocationException(String message, String faultCode, String faultString) {
        super(message);
        this.faultCode = faultCode;
        this.faultString = faultString;
    }

    public STSInvocationException(String message, Throwable cause) {
        super(message, cause);
    }

    public String getFaultCode() {
        return faultCode;
    }

    public String getFaultString() {
        return faultString;
    }
}
