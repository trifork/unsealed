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

public class IdCardBuilder extends AbstractSigningBuilder {

    private NSPEnv env;
    private String cpr;
    private String keystoreFromClassPath;
    private String keystoreFromFilePath;
    private InputStream keystoreFromInputStream;
    private KeyStore keystore;
    private String keystoreType;
    private char[] keystorePassword;
    private String email;
    private String role;
    private String occupation;
    private String authorizationCode;
    private String systemName;

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

    public UserIdCard buildUserIdCard() throws IOException, KeyStoreException, NoSuchAlgorithmException,
            CertificateException, UnrecoverableKeyException {

        String keystoreTp = keystoreType;

        KeyStore ks;
        if (keystore != null) {
            ks = keystore;
        } else {
            ks = loadKeystore(keystoreTp, keystoreFromFilePath);
        }

        X509Certificate certificate = (X509Certificate) ks.getCertificate(ks.aliases().nextElement());

        certificate.checkValidity();

        Key privateKey = ks.getKey(ks.aliases().nextElement(), keystorePassword);

        UserIdCard idCard = new UserIdCard(env, cpr, certificate, privateKey, email, role, occupation, authorizationCode,
                systemName);

        return idCard;
    }

    public SystemIdCard buildSystemIdCard() throws IOException, KeyStoreException, NoSuchAlgorithmException,
            CertificateException, UnrecoverableKeyException {

        String keystoreTp = keystoreType;

        KeyStore ks;
        if (keystore != null) {
            ks = keystore;
        } else {
            ks = loadKeystore(keystoreTp, keystoreFromFilePath);
        }

        X509Certificate certificate = (X509Certificate) ks.getCertificate(ks.aliases().nextElement());

        certificate.checkValidity();

        Key privateKey = ks.getKey(ks.aliases().nextElement(), keystorePassword);

        SystemIdCard idCard = new SystemIdCard(env, certificate, privateKey, systemName);

        return idCard;
    }

    private KeyStore loadKeystore(String keystoreTp, String keystoreFromFilePath) throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException {
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