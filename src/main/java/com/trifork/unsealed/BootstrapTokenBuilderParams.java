package com.trifork.unsealed;

public class BootstrapTokenBuilderParams extends AbstractSigningBuilderParams {
    NSPEnv env;
    String xml;
    String jwt;

    BootstrapTokenBuilderParams copy() {
        try {
            return (BootstrapTokenBuilderParams) this.clone();
        } catch (CloneNotSupportedException e) {
            throw new IllegalStateException("Should not happen", e);
        }
    }

}
