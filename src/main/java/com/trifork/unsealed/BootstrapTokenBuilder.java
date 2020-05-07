package com.trifork.unsealed;

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

public class BootstrapTokenBuilder {
    private NSPEnv env;
    private String xml;
    private String keystoreFromClassPath;
    private String keystoreFromFilePath;
    private InputStream keystoreFromInputStream;
    private KeyStore keystore;
    private String keystoreType;
    private char[] keystorePassword;

    public BootstrapTokenBuilder() {
    }

    private BootstrapTokenBuilder(NSPEnv env, String keystoreFromClassPath, String keystoreFromFilePath,
            InputStream keystoreFromInputStream, KeyStore keystore, String keystoreType, char[] keystorePassword,
            String xml) {
        this.env = env;
        this.keystoreFromClassPath = keystoreFromClassPath;
        this.keystoreFromFilePath = keystoreFromFilePath;
        this.keystoreFromInputStream = keystoreFromInputStream;
        this.keystore = keystore;
        this.keystoreType = keystoreType;
        this.keystorePassword = keystorePassword;
        this.xml = xml;
    }

    public BootstrapTokenBuilder env(NSPEnv env) {
        return new BootstrapTokenBuilder(env, keystoreFromClassPath, keystoreFromFilePath, keystoreFromInputStream,
                keystore, keystoreType, keystorePassword, xml);
    }

    public BootstrapTokenBuilder fromXml(String xml) {
        return new BootstrapTokenBuilder(env, keystoreFromClassPath, keystoreFromFilePath, keystoreFromInputStream,
                keystore, keystoreType, keystorePassword, xml);
    }

    public BootstrapTokenBuilder keystoreFromClassPath(String keystoreFromClassPath) {
        return new BootstrapTokenBuilder(env, keystoreFromClassPath, keystoreFromFilePath, keystoreFromInputStream,
                keystore, keystoreType, keystorePassword, xml);
    }

    public BootstrapTokenBuilder keystorePath(String keystorePath) {
        return new BootstrapTokenBuilder(env, keystoreFromClassPath, keystoreFromFilePath, keystoreFromInputStream,
                keystore, keystoreType, keystorePassword, xml);
    }

    public BootstrapTokenBuilder keystoreFromInputStream(InputStream is, String keystoreType) {
        return new BootstrapTokenBuilder(env, keystoreFromClassPath, keystoreFromFilePath, keystoreFromInputStream,
                keystore, keystoreType, keystorePassword, xml);
    }

    public BootstrapTokenBuilder keystorePassword(char[] keystorePassword) {
        return new BootstrapTokenBuilder(env, keystoreFromClassPath, keystoreFromFilePath, keystoreFromInputStream,
                keystore, keystoreType, keystorePassword, xml);
    }

    public BootstrapToken build() throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException,
            UnrecoverableKeyException {
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
                keystoreTp = IdCardBuilder.guessKeystoreType(keystoreFromClassPath);
            } else if (keystoreFromFilePath != null) {
                keystoreIs = new FileInputStream(new File(keystoreFromFilePath));
                keystoreTp = IdCardBuilder.guessKeystoreType(keystoreFromClassPath);
            } else {
                throw new IllegalStateException("No keystore specified");
            }

            ks = KeyStore.getInstance(keystoreTp);
            ks.load(keystoreIs, keystorePassword);

            
        }
        X509Certificate certificate = (X509Certificate) ks.getCertificate(ks.aliases().nextElement());

        Key privateKey = ks.getKey(ks.aliases().nextElement(), keystorePassword);


        return new BootstrapToken(env, certificate, privateKey, xml);
    }

}