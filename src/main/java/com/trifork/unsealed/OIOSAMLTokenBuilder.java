package com.trifork.unsealed;

import java.io.IOException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;

import javax.xml.parsers.ParserConfigurationException;

import org.w3c.dom.Element;
import org.xml.sax.SAXException;

public class OIOSAMLTokenBuilder extends AbstractBuilder<OIOSAMLTokenBuilderParams> {

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

    public OIOSAMLTokenBuilder spCertAndKey(CertAndKey spCertAndKey) {
        OIOSAMLTokenBuilderParams params = this.params.copy();
        params.spCertAndKey = spCertAndKey;
        return new OIOSAMLTokenBuilder(params);
    }

    public OIOSAMLTokenBuilder assertion(Element assertion) {
        OIOSAMLTokenBuilderParams params = this.params.copy();
        params.assertion = assertion;
        return new OIOSAMLTokenBuilder(params);
    }

    OIOSAMLToken build() throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException,
            UnrecoverableKeyException, ParserConfigurationException, SAXException {

        if (params.assertion != null) {
            return new OIOSAMLToken(params.env, params.spCertAndKey.certificate, params.spCertAndKey.privateKey,
                    params.assertion, "EncryptedAssertion".equals(params.assertion.getLocalName()));
        } else {
            return new OIOSAMLToken(params.env, params.spCertAndKey.certificate, params.spCertAndKey.privateKey, false,
                    params.xml);
        }
    }
}