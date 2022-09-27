package com.trifork.unsealed;

import static com.trifork.unsealed.KeystoreUtil.guessKeystoreType;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.Objects;
import java.util.stream.Stream;

public abstract class AbstractSigningBuilder {

    protected String keystoreFromClassPath;
    protected String keystoreFromFilePath;
    protected InputStream keystoreFromInputStream;
    protected KeyStore keystore;
    protected String keystoreType;
    protected char[] keystorePassword;
    protected X509Certificate certificate;
    protected Key privateKey;
    protected String keystoreAlias;

    protected AbstractSigningBuilder() {
    }

    protected AbstractSigningBuilder(String keystoreFromClassPath, String keystoreFromFilePath,
            InputStream keystoreFromInputStream, KeyStore keystore, String keystoreType, char[] keystorePassword, String keystoreAlias) {

        this.keystoreFromClassPath = keystoreFromClassPath;
        this.keystoreFromFilePath = keystoreFromFilePath;
        this.keystoreFromInputStream = keystoreFromInputStream;
        this.keystore = keystore;
        this.keystoreType = keystoreType;
        this.keystorePassword = keystorePassword;
        this.keystoreAlias = keystoreAlias;
    }

    protected void loadKeyStore() throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException, UnrecoverableKeyException {

        validateParameters();

        InputStream keystoreIs = null;
        String keystoreTp = keystoreType;

        KeyStore ks;
        if (keystore != null) {
            ks = keystore;
        } else {
            if (keystoreFromInputStream != null) {
                keystoreIs = keystoreFromInputStream;
            } else if (keystoreFromClassPath != null) {
                keystoreIs = Thread.currentThread().getContextClassLoader().getResourceAsStream(keystoreFromClassPath);
                keystoreTp = guessKeystoreType(keystoreFromClassPath);
            } else if (keystoreFromFilePath != null) {
                keystoreIs = new FileInputStream(new File(keystoreFromFilePath));
                keystoreTp = guessKeystoreType(keystoreFromClassPath);
            }

            ks = KeyStore.getInstance(keystoreTp);
            ks.load(keystoreIs, keystorePassword);
        }

        String alias = keystoreAlias != null ? keystoreAlias : ks.aliases().nextElement();

        certificate = (X509Certificate) ks.getCertificate(alias);

        if (certificate == null) {
            throw new IllegalArgumentException("No certificate found with alias \"" + alias + "\", found " + Collections.list(ks.aliases()));
        }

        certificate.checkValidity();

        privateKey = ks.getKey(alias, keystorePassword);
    }

    private void validateParameters() {
        if (Stream.of(keystoreFromClassPath, keystoreFromFilePath, keystoreFromInputStream, keystore).filter(Objects::nonNull).count() != 1) {
            throw new IllegalStateException("Exactly one of [keystoreFromClassPath, keystoreFromFilePath, keystoreFromInputStream, keystore] must be specified");
        }

        if (keystoreFromInputStream != null && keystoreType == null) {
            throw new IllegalStateException("When keystoreFromInputStream is specified, keystoreType must also be specified");
        }
    }
}
