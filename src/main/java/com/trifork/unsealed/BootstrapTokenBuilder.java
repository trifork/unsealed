package com.trifork.unsealed;

import java.io.IOException;
import java.io.InputStream;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;

public class BootstrapTokenBuilder extends AbstractSigningBuilder<BootstrapTokenBuilderParams> {

    public BootstrapTokenBuilder() {
        super(new BootstrapTokenBuilderParams());
    }

    private BootstrapTokenBuilder(BootstrapTokenBuilderParams params) {
        super(params);
    }

    public BootstrapTokenBuilder env(NSPEnv env) {
        var params = this.params.copy();
        
        params.env = env;

        return new BootstrapTokenBuilder(params);
    }

    public BootstrapTokenBuilder fromXml(String xml) {
        var params = this.params.copy();
        params.xml = xml;
        return new BootstrapTokenBuilder(params);
    }

    public BootstrapTokenBuilder fromJwt(String jwt) {
        var params = this.params.copy();
        params.jwt = jwt;
        return new BootstrapTokenBuilder(params);
    }

    public BootstrapTokenBuilder keystoreFromClassPath(String keystoreFromClassPath) {
        var params = this.params.copy();
        params.keystoreFromClassPath = keystoreFromClassPath;
        return new BootstrapTokenBuilder(params);
    }

    public BootstrapTokenBuilder keystoreFromInputStream(InputStream is, String keystoreType) {
        var params = this.params.copy();
        params.keystoreFromInputStream = is;
        params.keystoreType = keystoreType;
        return new BootstrapTokenBuilder(params);
    }

    public BootstrapTokenBuilder keystorePassword(char[] keystorePassword) {
        var params = this.params.copy();
        params.keystorePassword = keystorePassword;
        return new BootstrapTokenBuilder(params);
    }

    public BootstrapTokenBuilder keystoreAlias(String keystoreAlias) {
        var params = this.params.copy();
        params.keystoreAlias = keystoreAlias;
        return new BootstrapTokenBuilder(params);
    }

    public BootstrapToken build() throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException,
            UnrecoverableKeyException {

        loadKeyStore();

        return new BootstrapToken(params.env, certificate, privateKey, params.xml, params.jwt);
    }

}