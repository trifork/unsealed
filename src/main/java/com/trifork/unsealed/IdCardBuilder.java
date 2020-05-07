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

public class IdCardBuilder {

    private NSPEnv env;
    public final String cpr;
    public final String keystoreFromClassPath;
    public final String keystoreFromFilePath;
    public final InputStream keystoreFromInputStream;
    public final KeyStore keystore;
    public final String keystoreType;
    public final char[] keystorePassword;
    public final String email;
    public final String role;
    public final String occupation;
    public final String authorizationCode;
    public final String systemName;

    public IdCardBuilder() {
        this(null, null, null, null, null, null, null, null, null, null, null, null, null);
    }

    private IdCardBuilder(NSPEnv env, String cpr, String keystoreFromClassPath, String keystoreFromFilePath,
            InputStream keystoreFromInputStream, KeyStore keystore, String keystoreType, char[] keystorePassword,
            String email, String role, String occupation, String authorizationCode, String systemName) {

        this.env = env;
        this.cpr = cpr;
        this.keystoreFromClassPath = keystoreFromClassPath;
        this.keystoreFromFilePath = keystoreFromFilePath;
        this.keystoreFromInputStream = keystoreFromInputStream;
        this.keystore = keystore;
        this.keystoreType = keystoreType;
        this.keystorePassword = keystorePassword;
        this.email = email;
        this.role = role;
        this.occupation = occupation;
        this.authorizationCode = authorizationCode;
        this.systemName = systemName;

        validateArguments();
    }

    private void validateArguments() {

    }

    public IdCardBuilder env(NSPEnv env) {
        return new IdCardBuilder(env, cpr, keystoreFromClassPath, keystoreFromFilePath, keystoreFromInputStream,
                keystore, keystoreType, keystorePassword, email, role, occupation, authorizationCode, systemName);
    }

    public IdCardBuilder cpr(String cpr) {
        return new IdCardBuilder(env, cpr, keystoreFromClassPath, keystoreFromFilePath, keystoreFromInputStream,
                keystore, keystoreType, keystorePassword, email, role, occupation, authorizationCode, systemName);
    }

    public IdCardBuilder keystoreFromClassPath(String keystoreFromClassPath) {
        return new IdCardBuilder(env, cpr, keystoreFromClassPath, keystoreFromFilePath, keystoreFromInputStream,
                keystore, keystoreType, keystorePassword, email, role, occupation, authorizationCode, systemName);
    }

    public IdCardBuilder keystorePath(String keystorePath) {
        return new IdCardBuilder(env, cpr, keystoreFromClassPath, keystoreFromFilePath, keystoreFromInputStream,
                keystore, keystoreType, keystorePassword, email, role, occupation, authorizationCode, systemName);
    }

    public IdCardBuilder keystoreFromInputStream(InputStream is, String keystoreType) {
        return new IdCardBuilder(env, cpr, keystoreFromClassPath, keystoreFromFilePath, keystoreFromInputStream,
                keystore, keystoreType, keystorePassword, email, role, occupation, authorizationCode, systemName);
    }

    public IdCardBuilder keystorePassword(char[] keystorePassword) {
        return new IdCardBuilder(env, cpr, keystoreFromClassPath, keystoreFromFilePath, keystoreFromInputStream,
                keystore, keystoreType, keystorePassword, email, role, occupation, authorizationCode, systemName);
    }

    public IdCardBuilder email(String email) {
        return new IdCardBuilder(env, cpr, keystoreFromClassPath, keystoreFromFilePath, keystoreFromInputStream,
                keystore, keystoreType, keystorePassword, email, role, occupation, authorizationCode, systemName);
    }

    public IdCardBuilder role(String role) {
        return new IdCardBuilder(env, cpr, keystoreFromClassPath, keystoreFromFilePath, keystoreFromInputStream,
                keystore, keystoreType, keystorePassword, email, role, occupation, authorizationCode, systemName);
    }

    public IdCardBuilder occupation(String occupation) {
        return new IdCardBuilder(env, cpr, keystoreFromClassPath, keystoreFromFilePath, keystoreFromInputStream,
                keystore, keystoreType, keystorePassword, email, role, occupation, authorizationCode, systemName);
    }

    public IdCardBuilder authorizationCode(String authorizationCode) {
        return new IdCardBuilder(env, cpr, keystoreFromClassPath, keystoreFromFilePath, keystoreFromInputStream,
                keystore, keystoreType, keystorePassword, email, role, occupation, authorizationCode, systemName);
    }

    public IdCardBuilder systemName(String systemName) {
        return new IdCardBuilder(env, cpr, keystoreFromClassPath, keystoreFromFilePath, keystoreFromInputStream,
                keystore, keystoreType, keystorePassword, email, role, occupation, authorizationCode, systemName);
    }

    public IdCard build() throws IOException, KeyStoreException, NoSuchAlgorithmException, CertificateException,
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
                keystoreTp = guessKeystoreType(keystoreFromClassPath);
            } else if (keystoreFromFilePath != null) {
                keystoreIs = new FileInputStream(new File(keystoreFromFilePath));
                keystoreTp = guessKeystoreType(keystoreFromClassPath);
            } else {
                throw new IllegalStateException("No keystoreificate specified");
            }

            ks = KeyStore.getInstance(keystoreTp);
            ks.load(keystoreIs, keystorePassword);
        }

        X509Certificate certificate = (X509Certificate) ks.getCertificate(ks.aliases().nextElement());

        Key privateKey = ks.getKey(ks.aliases().nextElement(), keystorePassword);


        IdCard idCard = new IdCard(env, cpr, certificate, privateKey, email, role, occupation,
                authorizationCode, systemName);

        return idCard;
    }

    static String guessKeystoreType(String path) {
        return path.endsWith(".jks") ? "JKS" : "PKCS12";
    }
}