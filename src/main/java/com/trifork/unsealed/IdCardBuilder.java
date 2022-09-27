package com.trifork.unsealed;

import java.io.IOException;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;

import org.w3c.dom.Element;

public class IdCardBuilder extends AbstractSigningBuilder {

    private NSPEnv env;
    private String cpr;
    private String email;
    private String role = "urn:dk:healthcare:no-role";
    private String occupation;
    private String authorizationCode;
    private String systemName;
    private Element assertion;

    public IdCardBuilder() {
    }

    private IdCardBuilder(NSPEnv env, String cpr, String keystoreFromClassPath, String keystoreFromFilePath,
            InputStream keystoreFromInputStream, KeyStore keystore, String keystoreType, char[] keystorePassword,
            String keystoreAlias, String email, String role, String occupation, String authorizationCode,
            String systemName, Element assertion) {

        super(keystoreFromClassPath, keystoreFromFilePath,
                keystoreFromInputStream, keystore, keystoreType, keystorePassword, keystoreAlias);

        this.env = env;
        this.cpr = cpr;
        this.email = email;
        this.role = role;
        this.occupation = occupation;
        this.authorizationCode = authorizationCode;
        this.systemName = systemName;
        this.assertion = assertion;

        validateArguments();
    }

    private void validateArguments() {

    }

    public IdCardBuilder env(NSPEnv env) {
        return new IdCardBuilder(env, cpr, keystoreFromClassPath, keystoreFromFilePath, keystoreFromInputStream,
                keystore, keystoreType, keystorePassword, keystoreAlias, email, role, occupation, authorizationCode,
                systemName, assertion);
    }

    public IdCardBuilder cpr(String cpr) {
        return new IdCardBuilder(env, cpr, keystoreFromClassPath, keystoreFromFilePath, keystoreFromInputStream,
                keystore, keystoreType, keystorePassword, keystoreAlias, email, role, occupation, authorizationCode,
                systemName, assertion);
    }

    public IdCardBuilder keystoreFromClassPath(String keystoreFromClassPath) {
        return new IdCardBuilder(env, cpr, keystoreFromClassPath, keystoreFromFilePath, keystoreFromInputStream,
                keystore, keystoreType, keystorePassword, keystoreAlias, email, role, occupation, authorizationCode,
                systemName, assertion);
    }

    public IdCardBuilder keystorePath(String keystorePath) {
        return new IdCardBuilder(env, cpr, keystoreFromClassPath, keystoreFromFilePath, keystoreFromInputStream,
                keystore, keystoreType, keystorePassword, keystoreAlias, email, role, occupation, authorizationCode,
                systemName, assertion);
    }

    public IdCardBuilder keystoreFromInputStream(InputStream is, String keystoreType) {
        return new IdCardBuilder(env, cpr, keystoreFromClassPath, keystoreFromFilePath, keystoreFromInputStream,
                keystore, keystoreType, keystorePassword, keystoreAlias, email, role, occupation, authorizationCode,
                systemName, assertion);
    }

    public IdCardBuilder keystorePassword(char[] keystorePassword) {
        return new IdCardBuilder(env, cpr, keystoreFromClassPath, keystoreFromFilePath, keystoreFromInputStream,
                keystore, keystoreType, keystorePassword, keystoreAlias, email, role, occupation, authorizationCode,
                systemName, assertion);
    }

    public IdCardBuilder keystoreAlias(String keystoreAlias) {
        return new IdCardBuilder(env, cpr, keystoreFromClassPath, keystoreFromFilePath, keystoreFromInputStream,
                keystore, keystoreType, keystorePassword, keystoreAlias, email, role, occupation, authorizationCode,
                systemName, assertion);
    }

    public IdCardBuilder email(String email) {
        return new IdCardBuilder(env, cpr, keystoreFromClassPath, keystoreFromFilePath, keystoreFromInputStream,
                keystore, keystoreType, keystorePassword, keystoreAlias, email, role, occupation, authorizationCode,
                systemName, assertion);
    }

    public IdCardBuilder role(String role) {
        return new IdCardBuilder(env, cpr, keystoreFromClassPath, keystoreFromFilePath, keystoreFromInputStream,
                keystore, keystoreType, keystorePassword, keystoreAlias, email, role, occupation, authorizationCode,
                systemName, assertion);
    }

    public IdCardBuilder occupation(String occupation) {
        return new IdCardBuilder(env, cpr, keystoreFromClassPath, keystoreFromFilePath, keystoreFromInputStream,
                keystore, keystoreType, keystorePassword, keystoreAlias, email, role, occupation, authorizationCode,
                systemName, assertion);
    }

    public IdCardBuilder authorizationCode(String authorizationCode) {
        return new IdCardBuilder(env, cpr, keystoreFromClassPath, keystoreFromFilePath, keystoreFromInputStream,
                keystore, keystoreType, keystorePassword, keystoreAlias, email, role, occupation, authorizationCode,
                systemName, assertion);
    }

    public IdCardBuilder systemName(String systemName) {
        return new IdCardBuilder(env, cpr, keystoreFromClassPath, keystoreFromFilePath, keystoreFromInputStream,
                keystore, keystoreType, keystorePassword, keystoreAlias, email, role, occupation, authorizationCode,
                systemName, assertion);
    }

    public IdCardBuilder assertion(Element assertion) {
        return new IdCardBuilder(env, cpr, keystoreFromClassPath, keystoreFromFilePath, keystoreFromInputStream,
                keystore, keystoreType, keystorePassword, keystoreAlias, email, role, occupation, authorizationCode,
                systemName, assertion);
    }

    public UserIdCard buildUserIdCard() throws IOException, KeyStoreException, NoSuchAlgorithmException,
            CertificateException, UnrecoverableKeyException {

        UserIdCard idCard;

        if (assertion != null) {
            idCard = new UserIdCard(env, assertion);
        } else {
            loadKeyStore();
            idCard = new UserIdCard(env, cpr, certificate, privateKey, email, role, occupation, authorizationCode,
                    systemName);
        }


        return idCard;
    }

    public SystemIdCard buildSystemIdCard() throws IOException, KeyStoreException, NoSuchAlgorithmException,
            CertificateException, UnrecoverableKeyException {

        SystemIdCard idCard;

        if (assertion != null) {
            idCard = new SystemIdCard(env, assertion);

        } else {
            loadKeyStore();
            idCard = new SystemIdCard(env, certificate, privateKey, systemName);
        }

        return idCard;
    }
}