package com.trifork.unsealed;

import java.security.cert.X509Certificate;

public class BootstrapTokenIssuerParams extends AbstractBuilderParams {
    NSPEnv env;
    String cpr;
    String uuid;
    String cvr;
    String orgName;
    X509Certificate spCert;
    CertAndKey spCertAndKey;
    CertAndKey idpCertAndKey;

    BootstrapTokenIssuerParams copy() {
        try {
            return (BootstrapTokenIssuerParams) this.clone();
        } catch (CloneNotSupportedException e) {
            throw new IllegalStateException("Should not happen", e);
        }
    }

}
