package com.trifork.unsealed;

import static com.trifork.unsealed.SamlUtil.getSamlAttribute;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;

import javax.xml.parsers.ParserConfigurationException;

import org.w3c.dom.Element;
import org.xml.sax.SAXException;

public class IdCardBuilder extends AbstractBuilder<IdCardBuilderParams> {

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

    public IdCardBuilder certAndKey(CertAndKey certAndKey) {
        IdCardBuilderParams params = this.params.copy();
        params.certAndKey = certAndKey;
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

    public IdCardBuilder xml(String xml) {
        IdCardBuilderParams params = this.params.copy();
        params.xml = xml;
        return new IdCardBuilder(params);
    }

    public IdCard buildIdCard() throws IOException, KeyStoreException, NoSuchAlgorithmException,
            CertificateException, UnrecoverableKeyException, SAXException, ParserConfigurationException {

        IdCard idCard;

        Element assertion = null;
        if (params.assertion != null) {
            assertion = params.assertion;
        } else if (params.xml != null) {
            assertion = XmlUtil.getDocBuilder().parse(new ByteArrayInputStream(params.xml.getBytes(StandardCharsets.UTF_8))).getDocumentElement();
        }

        if (assertion != null) {
            fixIdAttribute(assertion);
            Element attributeStatement = XmlUtil.getChild(assertion, NsPrefixes.saml, "AttributeStatement");
            String idCardType = getSamlAttribute(attributeStatement, IdCard.SOSI_IDCARD_TYPE);
            switch (idCardType) {
                case "user":
                    idCard = new UserIdCard(params.env, assertion);
                    break;
                case "system":
                    idCard = new SystemIdCard(params.env, assertion);
                    break;
                default:
                    throw new IllegalArgumentException("Unexpected idcard type \"" + idCardType + "\"");
            }

            return idCard;

        } else {
            throw new IllegalArgumentException("Use buildUserIdCard or buildSystemIdCard when not building from existing assertion");
        }
    }

    private void fixIdAttribute(Element assertion) {
        if (assertion.getAttribute("id") != null) {
            assertion.setIdAttribute("id", true);
        }
    }

    public UserIdCard buildUserIdCard() throws IOException, KeyStoreException, NoSuchAlgorithmException,
            CertificateException, UnrecoverableKeyException, SAXException, ParserConfigurationException {

        UserIdCard idCard;

        Element assertion = null;
        if (params.assertion != null) {
            assertion = params.assertion;
        } else if (params.xml != null) {
            assertion = XmlUtil.getDocBuilder().parse(new ByteArrayInputStream(params.xml.getBytes(StandardCharsets.UTF_8))).getDocumentElement();
            if (assertion.getAttribute("id") != null) {
                assertion.setIdAttribute("id", true);
            }

        }

        if (assertion != null) {
            fixIdAttribute(assertion);
            idCard = new UserIdCard(params.env, assertion);
        } else {
            idCard = new UserIdCard(params.env, params.cpr, params.certAndKey.certificate,
                    params.certAndKey.privateKey, params.email, params.role, params.occupation,
                    params.authorizationCode,
                    params.systemName);
        }

        return idCard;
    }

    public SystemIdCard buildSystemIdCard() throws IOException, KeyStoreException, NoSuchAlgorithmException,
            CertificateException, UnrecoverableKeyException, SAXException, ParserConfigurationException {

        SystemIdCard idCard;

        Element assertion = null;
        if (params.assertion != null) {
            assertion = params.assertion;
        } else if (params.xml != null) {
            assertion = XmlUtil.getDocBuilder().parse(new ByteArrayInputStream(params.xml.getBytes(StandardCharsets.UTF_8))).getDocumentElement();
        }

        if (assertion != null) {
            fixIdAttribute(assertion);
            idCard = new SystemIdCard(params.env, assertion);

        } else {
            idCard = new SystemIdCard(params.env, params.certAndKey.certificate, params.certAndKey.privateKey, params.systemName);
        }

        return idCard;
    }
}