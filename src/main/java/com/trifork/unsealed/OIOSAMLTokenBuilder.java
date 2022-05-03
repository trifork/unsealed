package com.trifork.unsealed;

import java.io.IOException;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;

import javax.xml.parsers.ParserConfigurationException;

import org.w3c.dom.Element;
import org.xml.sax.SAXException;

public class OIOSAMLTokenBuilder extends AbstractSigningBuilder {
    private NSPEnv env;
    private Element assertion;
    private String xml;

    public OIOSAMLTokenBuilder() {
    }

    private OIOSAMLTokenBuilder(NSPEnv env, String keystoreFromClassPath, String keystoreFromFilePath,
            InputStream keystoreFromInputStream, KeyStore keystore, String keystoreType, char[] keystorePassword,
            String keystoreAlias, Element assertion, String xml) {

        super(keystoreFromClassPath, keystoreFromFilePath,
                keystoreFromInputStream, keystore, keystoreType, keystorePassword, keystoreAlias);

        this.env = env;
        this.assertion = assertion;
        this.xml = xml;
    }

    public OIOSAMLTokenBuilder env(NSPEnv env) {
        return new OIOSAMLTokenBuilder(env, keystoreFromClassPath, keystoreFromFilePath, keystoreFromInputStream,
                keystore, keystoreType, keystorePassword, keystoreAlias, assertion, xml);
    }

    public OIOSAMLTokenBuilder xml(String xml) {
        return new OIOSAMLTokenBuilder(env, keystoreFromClassPath, keystoreFromFilePath, keystoreFromInputStream,
                keystore, keystoreType, keystorePassword, keystoreAlias, assertion, xml);
    }

    public OIOSAMLTokenBuilder keystoreFromClassPath(String keystoreFromClassPath) {
        return new OIOSAMLTokenBuilder(env, keystoreFromClassPath, keystoreFromFilePath, keystoreFromInputStream,
                keystore, keystoreType, keystorePassword, keystoreAlias, assertion, xml);
    }

    public OIOSAMLTokenBuilder keystorePath(String keystorePath) {
        return new OIOSAMLTokenBuilder(env, keystoreFromClassPath, keystoreFromFilePath, keystoreFromInputStream,
                keystore, keystoreType, keystorePassword, keystoreAlias, assertion, xml);
    }

    public OIOSAMLTokenBuilder keystoreFromInputStream(InputStream is, String keystoreType) {
        return new OIOSAMLTokenBuilder(env, keystoreFromClassPath, keystoreFromFilePath, keystoreFromInputStream,
                keystore, keystoreType, keystorePassword, keystoreAlias, assertion, xml);
    }

    public OIOSAMLTokenBuilder keystorePassword(char[] keystorePassword) {
        return new OIOSAMLTokenBuilder(env, keystoreFromClassPath, keystoreFromFilePath, keystoreFromInputStream,
                keystore, keystoreType, keystorePassword, keystoreAlias, assertion, xml);
    }

    public OIOSAMLTokenBuilder keystoreAlias(String keystoreAlias) {
        return new OIOSAMLTokenBuilder(env, keystoreFromClassPath, keystoreFromFilePath, keystoreFromInputStream,
                keystore, keystoreType, keystorePassword, keystoreAlias, assertion, xml);
    }

    public OIOSAMLTokenBuilder assertion(Element assertion) {
        return new OIOSAMLTokenBuilder(env, keystoreFromClassPath, keystoreFromFilePath, keystoreFromInputStream,
                keystore, keystoreType, keystorePassword, keystoreAlias, assertion, xml);
    }

    OIOSAMLToken build() throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException,
            UnrecoverableKeyException, ParserConfigurationException, SAXException {

        loadKeyStore();

        if (assertion != null) {
            return new OIOSAMLToken(env, privateKey, certificate, assertion, "EncryptedAssertion".equals(assertion.getTagName()));
        } else {
            return new OIOSAMLToken(env, privateKey, certificate, false, xml);
        }
    }
}