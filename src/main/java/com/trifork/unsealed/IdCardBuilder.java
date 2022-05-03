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

        super(keystoreFromClassPath, keystoreFromFilePath,
                keystoreFromInputStream, keystore, keystoreType, keystorePassword);

        this.env = env;
        this.cpr = cpr;
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

        loadKeyStore();

        UserIdCard idCard = new UserIdCard(env, cpr, certificate, privateKey, email, role, occupation,
                authorizationCode,
                systemName);

        return idCard;
    }

    public SystemIdCard buildSystemIdCard() throws IOException, KeyStoreException, NoSuchAlgorithmException,
            CertificateException, UnrecoverableKeyException {

        loadKeyStore();
                
        SystemIdCard idCard = new SystemIdCard(env, certificate, privateKey, systemName);

        return idCard;
    }
}