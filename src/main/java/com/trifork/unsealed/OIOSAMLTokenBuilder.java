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

    /**
     * Specify the NSP environment which will be the context for OIOSAML tokens built by this builder
     * 
     * @param env
     *            Either {@link NSPEnv#fromUrl(stsBaseUrl)} or one of the enum values of {@link com.trifork.unsealed.NSPTestEnv}
     * @return A new immutable builder instance that encapsulates the supplied parameter
     */
    public OIOSAMLTokenBuilder env(NSPEnv env) {
        OIOSAMLTokenBuilderParams params = this.params.copy();
        params.env = env;
        return new OIOSAMLTokenBuilder(params);
    }

    /**
     * @deprecated Renamed to {@link OIOSAMLTokenBuilder#fromXml(String)} for consistency with other builders
     * @param xml
     * @return
     */
    public OIOSAMLTokenBuilder xml(String xml) {
        return fromXml(xml);
    }

    /**
     * Build OIOSAMLToken from a String representation of the assertion XML.
     * 
     * @param xml
     *            An OIOSAML token represented as an XML String
     * @return A new immutable builder instance that encapsulates the supplied parameter
     */
    public OIOSAMLTokenBuilder fromXml(String xml) {
        OIOSAMLTokenBuilderParams params = this.params.copy();
        params.xml = xml;
        return new OIOSAMLTokenBuilder(params);
    }

    /**
     * Specify the SP (Service Provider) {@link CertAndKey} (certificate keypair). This is used to decrypt encrypted OIOSAML tokens (and in Moces2 to identify
     * the service provider when exchanging the OIOSAMLToken to an IDCard).
     * 
     * @see OIOSAMLToken#decrypt()
     * 
     * @param spCertAndKey
     *            The SP keypair
     * @return
     */
    public OIOSAMLTokenBuilder spCertAndKey(CertAndKey spCertAndKey) {
        OIOSAMLTokenBuilderParams params = this.params.copy();
        params.spCertAndKey = spCertAndKey;
        return new OIOSAMLTokenBuilder(params);
    }

    /**
     * Build OIOSAMLToken from a {@link org.w3c.dom.Element} representation of the assertion (XML)
     * 
     * @param assertion
     * @return A new immutable builder instance that encapsulates the supplied parameter
     */
    public OIOSAMLTokenBuilder assertion(Element assertion) {
        OIOSAMLTokenBuilderParams params = this.params.copy();
        params.assertion = assertion;
        return new OIOSAMLTokenBuilder(params);
    }

    /**
     * Build an OIOSAMLToken from the supplied parameters.
     * @return the built OIOSAMLToken
     * @throws KeyStoreException
     * @throws NoSuchAlgorithmException
     * @throws CertificateException
     * @throws IOException
     * @throws UnrecoverableKeyException
     * @throws ParserConfigurationException
     * @throws SAXException
     */
    public OIOSAMLToken build() throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException,
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