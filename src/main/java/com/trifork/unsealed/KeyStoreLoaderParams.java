package com.trifork.unsealed;

import java.io.InputStream;
import java.security.KeyStore;

public class KeyStoreLoaderParams implements Cloneable {
    protected String fromClassPath;
    protected String fromFilePath;
    protected InputStream fromInputStream;
    protected KeyStore keyStore;
    protected String type;
    protected char[] password;
    protected String alias;

    KeyStoreLoaderParams copy() {
        try {
            return (KeyStoreLoaderParams) this.clone();
        } catch (CloneNotSupportedException e) {
            throw new IllegalStateException("Should not happen", e);
        }
    }
}
