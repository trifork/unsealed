package com.trifork.unsealed;

public class OIOSAMLTokenIssuerParams extends AbstractSigningBuilderParams {
    String subjectName;
    String recipient;
    String audience;
    String issuer;
    String uid;
    String pidNumber;
    String cvrNumber;
    String ridNumber;
    String cprNumber;
    String surName;
    String commonName;
    String email;
    String organisationName;
    public CertAndKey idpCertAndKey;

    OIOSAMLTokenIssuerParams copy() {
        try {
            return (OIOSAMLTokenIssuerParams) this.clone();
        } catch (CloneNotSupportedException e) {
            throw new IllegalStateException("Should not happen", e);
        }
    }
}
