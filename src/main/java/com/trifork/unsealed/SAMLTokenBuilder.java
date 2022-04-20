package com.trifork.unsealed;

import static com.trifork.unsealed.KeystoreUtil.guessKeystoreType;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import org.w3c.dom.Element;

public class SAMLTokenBuilder extends AbstractSigningBuilder {
    private NSPEnv env;
    private String keystoreFromClassPath;
    private String keystoreFromFilePath;
    private InputStream keystoreFromInputStream;
    private KeyStore keystore;
    private String keystoreType;
    private char[] keystorePassword;
    private Element assertion;
    private String xml;

    public SAMLTokenBuilder() {
    }

    private SAMLTokenBuilder(NSPEnv env, String keystoreFromClassPath, String keystoreFromFilePath,
            InputStream keystoreFromInputStream, KeyStore keystore, String keystoreType, char[] keystorePassword,
            Element assertion, String xml) {
        this.env = env;
        this.keystoreFromClassPath = keystoreFromClassPath;
        this.keystoreFromFilePath = keystoreFromFilePath;
        this.keystoreFromInputStream = keystoreFromInputStream;
        this.keystore = keystore;
        this.keystorePassword = keystorePassword;
        this.assertion = assertion;
        this.xml = xml;
    }

    public SAMLTokenBuilder env(NSPEnv env) {
        return new SAMLTokenBuilder(env, keystoreFromClassPath, keystoreFromFilePath, keystoreFromInputStream, keystore, keystoreType, keystorePassword, assertion, xml);
    }

    public SAMLTokenBuilder xml(String xml) {
        return new SAMLTokenBuilder(env, keystoreFromClassPath, keystoreFromFilePath, keystoreFromInputStream, keystore, keystoreType, keystorePassword, assertion, xml);
    }

    public SAMLTokenBuilder keystoreFromClassPath(String keystoreFromClassPath) {
        return new SAMLTokenBuilder(env, keystoreFromClassPath, keystoreFromFilePath, keystoreFromInputStream, keystore, keystoreType, keystorePassword, assertion, xml);
    }

    public SAMLTokenBuilder keystorePath(String keystorePath) {
        return new SAMLTokenBuilder(env, keystoreFromClassPath, keystoreFromFilePath, keystoreFromInputStream, keystore, keystoreType, keystorePassword, assertion, xml);
    }

    public SAMLTokenBuilder keystoreFromInputStream(InputStream is, String keystoreType) {
        return new SAMLTokenBuilder(env, keystoreFromClassPath, keystoreFromFilePath, keystoreFromInputStream, keystore, keystoreType, keystorePassword, assertion, xml);
    }

    public SAMLTokenBuilder keystorePassword(char[] keystorePassword) {
        return new SAMLTokenBuilder(env, keystoreFromClassPath, keystoreFromFilePath, keystoreFromInputStream, keystore, keystoreType, keystorePassword, assertion, xml);
    }

    public SAMLTokenBuilder assertion(Element assertion) {
        return new SAMLTokenBuilder(env, keystoreFromClassPath, keystoreFromFilePath, keystoreFromInputStream, keystore, keystoreType, keystorePassword, assertion, xml);
    }

    OIOSAMLToken build() throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException, UnrecoverableKeyException {
        KeyStore ks = loadKeystore(keystoreType, keystoreFromFilePath);
        X509Certificate certificate = (X509Certificate) ks.getCertificate(ks.aliases().nextElement());

        certificate.checkValidity();

        Key privateKey = ks.getKey(ks.aliases().nextElement(), keystorePassword);

        return new OIOSAMLToken(env, privateKey, certificate, assertion, assertion != null && "EncryptedAssertion".equals(assertion.getTagName()), xml);
    }

    private KeyStore loadKeystore(String keystoreTp, String keystoreFromFilePath)
            throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException {
        InputStream keystoreIs;
        KeyStore ks;

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

        return ks;
    }

}