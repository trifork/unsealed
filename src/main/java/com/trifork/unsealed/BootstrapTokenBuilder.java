package com.trifork.unsealed;

import java.io.IOException;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;

public class BootstrapTokenBuilder extends AbstractSigningBuilder {
    private NSPEnv env;
    private String xml;
    private String jwt;

    public BootstrapTokenBuilder() {
        super();
    }

    private BootstrapTokenBuilder(NSPEnv env, String keystoreFromClassPath, String keystoreFromFilePath,
            InputStream keystoreFromInputStream, KeyStore keystore, String keystoreType, char[] keystorePassword,
            String xml, String jwt) {

        super(keystoreFromClassPath, keystoreFromFilePath,
                keystoreFromInputStream, keystore, keystoreType, keystorePassword);

        this.env = env;
        this.xml = xml;
        this.jwt = jwt;
    }

    public BootstrapTokenBuilder env(NSPEnv env) {
        return new BootstrapTokenBuilder(env, keystoreFromClassPath, keystoreFromFilePath, keystoreFromInputStream,
                keystore, keystoreType, keystorePassword, xml, jwt);
    }

    public BootstrapTokenBuilder fromXml(String xml) {
        return new BootstrapTokenBuilder(env, keystoreFromClassPath, keystoreFromFilePath, keystoreFromInputStream,
                keystore, keystoreType, keystorePassword, xml, jwt);
    }

    public BootstrapTokenBuilder fromJwt(String jwt) {
        return new BootstrapTokenBuilder(env, keystoreFromClassPath, keystoreFromFilePath, keystoreFromInputStream,
                keystore, keystoreType, keystorePassword, xml, jwt);
    }

    public BootstrapTokenBuilder keystoreFromClassPath(String keystoreFromClassPath) {
        return new BootstrapTokenBuilder(env, keystoreFromClassPath, keystoreFromFilePath, keystoreFromInputStream,
                keystore, keystoreType, keystorePassword, xml, jwt);
    }

    public BootstrapTokenBuilder keystorePath(String keystorePath) {
        return new BootstrapTokenBuilder(env, keystoreFromClassPath, keystoreFromFilePath, keystoreFromInputStream,
                keystore, keystoreType, keystorePassword, xml, jwt);
    }

    public BootstrapTokenBuilder keystoreFromInputStream(InputStream is, String keystoreType) {
        return new BootstrapTokenBuilder(env, keystoreFromClassPath, keystoreFromFilePath, keystoreFromInputStream,
                keystore, keystoreType, keystorePassword, xml, jwt);
    }

    public BootstrapTokenBuilder keystorePassword(char[] keystorePassword) {
        return new BootstrapTokenBuilder(env, keystoreFromClassPath, keystoreFromFilePath, keystoreFromInputStream,
                keystore, keystoreType, keystorePassword, xml, jwt);
    }

    public BootstrapToken build() throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException,
            UnrecoverableKeyException {

        loadKeyStore();

        return new BootstrapToken(env, certificate, privateKey, xml, jwt);
    }

}