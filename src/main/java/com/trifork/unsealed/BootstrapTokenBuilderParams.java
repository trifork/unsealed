package com.trifork.unsealed;

public class BootstrapTokenBuilderParams extends AbstractBuilderParams {
    NSPEnv env;
    String xml;
    String jwt;
    CertAndKey spCertAndKey;

    BootstrapTokenBuilderParams copy() {
        try {
            return (BootstrapTokenBuilderParams) this.clone();
        } catch (CloneNotSupportedException e) {
            throw new IllegalStateException("Should not happen", e);
        }
    }

}
