package com.trifork.unsealed;

import java.security.cert.X509Certificate;

public class OIOSAMLTokenIssuerParams extends AbstractBuilderParams {
    String recipient;
    String audience;
    String issuer;
    String uid;
    String pidNumber;
    String cvrNumber;
    String ridNumber;
    String cprNumber;
    String cprUuid;
    String profUuid;
    String surName;
    String commonName;
    String email;
    String organisationName;
    CertAndKey idpCertAndKey;
    X509Certificate spCert;

    OIOSAMLTokenIssuerParams copy() {
        try {
            return (OIOSAMLTokenIssuerParams) this.clone();
        } catch (CloneNotSupportedException e) {
            throw new IllegalStateException("Should not happen", e);
        }
    }
}
