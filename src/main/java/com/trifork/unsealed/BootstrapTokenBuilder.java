package com.trifork.unsealed;

import java.io.IOException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;

public class BootstrapTokenBuilder extends AbstractBuilder<BootstrapTokenBuilderParams> {

    public BootstrapTokenBuilder() {
        super(new BootstrapTokenBuilderParams());
    }

    private BootstrapTokenBuilder(BootstrapTokenBuilderParams params) {
        super(params);
    }

    /**
     * Specify the NSP environment which will be the context for bootstrap tokens built by this builder
     * 
     * @param env Either {@link NSPEnv#fromUrl(stsBaseUrl)} or one of the enum values of {@link com.trifork.unsealed.NSPTestEnv}
     * @return A new immutable builder instance that encapsulates the supplied parameter
     */
    public BootstrapTokenBuilder env(NSPEnv env) {
        var params = this.params.copy();

        params.env = env;

        return new BootstrapTokenBuilder(params);
    }

    /**
     * Set the supplied XML String as the bootstrap token source. 
     * @param xml A bootstrap token represented as an XML String
     * @return A new immutable builder instance that encapsulates the supplied parameter
     */
    public BootstrapTokenBuilder fromXml(String xml) {
        var params = this.params.copy();
        params.xml = xml;
        return new BootstrapTokenBuilder(params);
    }

    /**
     * Set the supplied JWT String as the bootstrap token source.
     * @param jwt A bootstrap token represented as a JWT String
     * @return
     */
    public BootstrapTokenBuilder fromJwt(String jwt) {
        var params = this.params.copy();
        params.jwt = jwt;
        return new BootstrapTokenBuilder(params);
    }

    /**
     * Specify the SP (Service Provider) {@link CertAndKey} (certificate keypair). This is used if the issued bootstrap token is exchanged to an IDWS IdentityToken or a DGWS
     * Idcard.
     * @see BootstrapToken#exchangeToIdentityToken(String, String)
     * @see BootstrapToken#exchangeToIdentityToken(String, String, String, BootstrapToken.OnBehalfOfClaimType)
     * 
     * @param spCertAndKey The SP keypair
     * @return
     */
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