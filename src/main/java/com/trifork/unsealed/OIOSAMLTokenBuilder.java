package com.trifork.unsealed;

import java.io.IOException;
import java.io.InputStream;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;

import javax.xml.parsers.ParserConfigurationException;

import org.w3c.dom.Element;
import org.xml.sax.SAXException;

public class OIOSAMLTokenBuilder extends AbstractSigningBuilder<OIOSAMLTokenBuilderParams> {

    public OIOSAMLTokenBuilder() {
        super(new OIOSAMLTokenBuilderParams());
    }

    private OIOSAMLTokenBuilder(OIOSAMLTokenBuilderParams params) {
        super(params);
    }

    public OIOSAMLTokenBuilder env(NSPEnv env) {
        OIOSAMLTokenBuilderParams params = this.params.copy();
        params.env = env;
        return new OIOSAMLTokenBuilder(params);
    }

    public OIOSAMLTokenBuilder xml(String xml) {
        OIOSAMLTokenBuilderParams params = this.params.copy();
        params.xml = xml;
        return new OIOSAMLTokenBuilder(params);
    }

    public OIOSAMLTokenBuilder keystoreFromClassPath(String keystoreFromClassPath) {
        OIOSAMLTokenBuilderParams params = this.params.copy();
        params.keystoreFromClassPath = keystoreFromClassPath;
        return new OIOSAMLTokenBuilder(params);
    }

    public OIOSAMLTokenBuilder keystoreFromInputStream(InputStream is, String keystoreType) {
        OIOSAMLTokenBuilderParams params = this.params.copy();
        params.keystoreFromInputStream = is;
        params.keystoreType = keystoreType;
        return new OIOSAMLTokenBuilder(params);
    }

    public OIOSAMLTokenBuilder keystorePassword(char[] keystorePassword) {
        OIOSAMLTokenBuilderParams params = this.params.copy();
        params.keystorePassword = keystorePassword;
        return new OIOSAMLTokenBuilder(params);
    }

    public OIOSAMLTokenBuilder keystoreAlias(String keystoreAlias) {
        OIOSAMLTokenBuilderParams params = this.params.copy();
        params.keystoreAlias = keystoreAlias;
        return new OIOSAMLTokenBuilder(params);
    }

    public OIOSAMLTokenBuilder assertion(Element assertion) {
        OIOSAMLTokenBuilderParams params = this.params.copy();
        params.assertion = assertion;
        return new OIOSAMLTokenBuilder(params);
    }

    OIOSAMLToken build() throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException,
            UnrecoverableKeyException, ParserConfigurationException, SAXException {

        loadKeyStore();

        if (params.assertion != null) {
            return new OIOSAMLToken(params.env, privateKey, certificate, params.assertion, "EncryptedAssertion".equals(params.assertion.getLocalName()));
        } else {
            return new OIOSAMLToken(params.env, privateKey, certificate, false, params.xml);
        }
    }
}