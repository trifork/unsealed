package com.trifork.unsealed;

import java.io.IOException;
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

    public BootstrapTokenBuilder spCertAndKey(CertAndKey spCertAndKey) {
        var params = this.params.copy();
        params.spCertAndKey = spCertAndKey;
        return new BootstrapTokenBuilder(params);
    }

    public BootstrapToken build() throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException,
            UnrecoverableKeyException {

        return new BootstrapToken(params.env, params.spCertAndKey.certificate, params.spCertAndKey.privateKey,
                params.xml, params.jwt);
    }

}