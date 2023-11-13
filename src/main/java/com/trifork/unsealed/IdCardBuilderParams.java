package com.trifork.unsealed;

import org.w3c.dom.Element;

public class IdCardBuilderParams extends AbstractSigningBuilderParams {
    NSPEnv env;
    String cpr;
    String email;
    String role = "urn:dk:healthcare:no-role";
    String occupation;
    String authorizationCode;
    String systemName;
    Element assertion;

    IdCardBuilderParams copy() {
        try {
            return (IdCardBuilderParams) this.clone();
        } catch (CloneNotSupportedException e) {
            throw new IllegalStateException("Should not happen", e);
        }
    }
}
