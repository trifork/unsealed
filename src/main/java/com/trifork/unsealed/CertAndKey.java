package com.trifork.unsealed;

import java.security.PrivateKey;
import java.security.cert.X509Certificate;

public class CertAndKey {
    public final X509Certificate certificate;
    public final PrivateKey privateKey;

    public CertAndKey(X509Certificate certificate, PrivateKey privateKey) {
        this.certificate = certificate;
        this.privateKey = privateKey;
    }
}