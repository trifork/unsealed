package com.trifork.unsealed;

import org.w3c.dom.Element;

public class IdCardBuilderParams extends AbstractBuilderParams {
    NSPEnv env;
    String cpr;
    String email;
    String role = "urn:dk:healthcare:no-role";
    String occupation;
    String authorizationCode;
    String systemName;
    Element assertion;
    String xml;
    CertAndKey certAndKey;

    IdCardBuilderParams copy() {
        try {
            return (IdCardBuilderParams) this.clone();
        } catch (CloneNotSupportedException e) {
            throw new IllegalStateException("Should not happen", e);
        }
    }
}
