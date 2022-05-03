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

public abstract class AbstractSigningBuilder {

    protected String keystoreFromClassPath;
    protected String keystoreFromFilePath;
    protected InputStream keystoreFromInputStream;
    protected KeyStore keystore;
    protected String keystoreType;
    protected char[] keystorePassword;
    protected X509Certificate certificate;
    protected Key privateKey;

    protected AbstractSigningBuilder() {
    }

    protected AbstractSigningBuilder(String keystoreFromClassPath, String keystoreFromFilePath,
            InputStream keystoreFromInputStream, KeyStore keystore, String keystoreType, char[] keystorePassword) {

        this.keystoreFromClassPath = keystoreFromClassPath;
        this.keystoreFromFilePath = keystoreFromFilePath;
        this.keystoreFromInputStream = keystoreFromInputStream;
        this.keystore = keystore;
        this.keystoreType = keystoreType;
        this.keystorePassword = keystorePassword;
    }

    protected void loadKeyStore() throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException, UnrecoverableKeyException {
        InputStream keystoreIs;
        String keystoreTp = keystoreType;

        KeyStore ks;
        if (keystore != null) {
            ks = keystore;
        } else {
            if (keystoreFromInputStream != null) {
                keystoreIs = keystoreFromInputStream;
                if (keystoreType == null) {
                    throw new IllegalStateException("KeystoreType must be specified with keystoreFromInputStream");
                }
            } else if (keystoreFromClassPath != null) {
                keystoreIs = Thread.currentThread().getContextClassLoader().getResourceAsStream(keystoreFromClassPath);
                keystoreTp = guessKeystoreType(keystoreFromClassPath);
            } else if (keystoreFromFilePath != null) {
                keystoreIs = new FileInputStream(new File(keystoreFromFilePath));
                keystoreTp = guessKeystoreType(keystoreFromClassPath);
            } else {
                throw new IllegalStateException("No keystore specified");
            }

            ks = KeyStore.getInstance(keystoreTp);
            ks.load(keystoreIs, keystorePassword);
        }

        certificate = (X509Certificate) ks.getCertificate(ks.aliases().nextElement());

        certificate.checkValidity();

        privateKey = ks.getKey(ks.aliases().nextElement(), keystorePassword);
    }
}
