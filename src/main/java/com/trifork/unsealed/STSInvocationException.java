package com.trifork.unsealed;

public class STSInvocationException extends Exception {
    private String faultCode;
    private String faultString;
    private String faultActor;

    public STSInvocationException(String message, String faultCode, String faultString, String faultActor) {
        super(message);
        this.faultCode = faultCode;
        this.faultString = faultString;
        this.faultActor = faultActor;
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

    public String getFaultActor() {
        return faultActor;
    }
}
