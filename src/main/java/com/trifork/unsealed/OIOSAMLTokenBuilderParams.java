package com.trifork.unsealed;

import org.w3c.dom.Element;

public class OIOSAMLTokenBuilderParams extends AbstractSigningBuilderParams {
    NSPEnv env;
    Element assertion;
    String xml;

    OIOSAMLTokenBuilderParams copy() {
        try {
            return (OIOSAMLTokenBuilderParams) this.clone();
        } catch (CloneNotSupportedException e) {
            throw new IllegalStateException("Should not happen", e);
        }
    }
}
