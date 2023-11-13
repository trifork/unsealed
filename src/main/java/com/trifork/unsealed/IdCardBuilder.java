package com.trifork.unsealed;

import java.io.IOException;
import java.io.InputStream;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;

import org.w3c.dom.Element;

public class IdCardBuilder extends AbstractSigningBuilder<IdCardBuilderParams> {

    public IdCardBuilder() {
        super(new IdCardBuilderParams());
    }

    private IdCardBuilder(IdCardBuilderParams params) {

        super(params);

        validateArguments();
    }

    private void validateArguments() {

    }

    public IdCardBuilder env(NSPEnv env) {
        IdCardBuilderParams params = this.params.copy();
        params.env = env;
        return new IdCardBuilder(params);
    }

    public IdCardBuilder cpr(String cpr) {
        IdCardBuilderParams params = this.params.copy();
        params.cpr = cpr;
        return new IdCardBuilder(params);
    }

    public IdCardBuilder keystoreFromClassPath(String keystoreFromClassPath) {
        IdCardBuilderParams params = this.params.copy();
        params.keystoreFromClassPath = keystoreFromClassPath;
        return new IdCardBuilder(params);
    }

    public IdCardBuilder keystoreFromInputStream(InputStream is, String keystoreType) {
        IdCardBuilderParams params = this.params.copy();
        params.keystoreFromInputStream = is;
        params.keystoreType = keystoreType;
        return new IdCardBuilder(params);
    }

    public IdCardBuilder keystorePassword(char[] keystorePassword) {
        IdCardBuilderParams params = this.params.copy();
        params.keystorePassword = keystorePassword;
        return new IdCardBuilder(params);
    }

    public IdCardBuilder keystoreAlias(String keystoreAlias) {
        IdCardBuilderParams params = this.params.copy();
        params.keystoreAlias = keystoreAlias;
        return new IdCardBuilder(params);
    }

    public IdCardBuilder email(String email) {
        IdCardBuilderParams params = this.params.copy();
        params.email = email;
        return new IdCardBuilder(params);
    }

    public IdCardBuilder role(String role) {
        IdCardBuilderParams params = this.params.copy();
        params.role = role; 
        return new IdCardBuilder(params);
    }

    public IdCardBuilder occupation(String occupation) {
        IdCardBuilderParams params = this.params.copy();
        params.occupation = occupation;
        return new IdCardBuilder(params);
    }

    public IdCardBuilder authorizationCode(String authorizationCode) {
        IdCardBuilderParams params = this.params.copy();
        params.authorizationCode = authorizationCode;
        return new IdCardBuilder(params);
    }

    public IdCardBuilder systemName(String systemName) {
        IdCardBuilderParams params = this.params.copy();
        params.systemName = systemName;
        return new IdCardBuilder(params);
    }

    public IdCardBuilder assertion(Element assertion) {
        IdCardBuilderParams params = this.params.copy();
        params.assertion = assertion;
        return new IdCardBuilder(params);
    }

    public UserIdCard buildUserIdCard() throws IOException, KeyStoreException, NoSuchAlgorithmException,
            CertificateException, UnrecoverableKeyException {

        UserIdCard idCard;

        if (params.assertion != null) {
            idCard = new UserIdCard(params.env, params.assertion);
        } else {
            loadKeyStore();
            idCard = new UserIdCard(params.env, params.cpr, certificate, privateKey, params.email, params.role, params.occupation, params.authorizationCode,
                    params.systemName);
        }


        return idCard;
    }

    public SystemIdCard buildSystemIdCard() throws IOException, KeyStoreException, NoSuchAlgorithmException,
            CertificateException, UnrecoverableKeyException {

        SystemIdCard idCard;

        if (params.assertion != null) {
            idCard = new SystemIdCard(params.env, params.assertion);

        } else {
            loadKeyStore();
            idCard = new SystemIdCard(params.env, certificate, privateKey, params.systemName);
        }

        return idCard;
    }
}