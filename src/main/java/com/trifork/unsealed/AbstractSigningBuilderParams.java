package com.trifork.unsealed;

import java.io.InputStream;
import java.security.KeyStore;

public class AbstractSigningBuilderParams implements Cloneable {
    protected String keystoreFromClassPath;
    protected String keystoreFromFilePath;
    protected InputStream keystoreFromInputStream;
    protected KeyStore keystore;
    protected String keystoreType;
    protected char[] keystorePassword;
    protected String keystoreAlias;
}
