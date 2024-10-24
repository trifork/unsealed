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

    /**
     * Specify the NSP environment which will be the context for IdCards built by this builder
     * 
     * @param env Either {@link NSPEnv#fromUrl(String)} or one of the enum values of {@link NSPTestEnv}
     * @return A new immutable builder instance that encapsulates the supplied parameter
     */
    public IdCardBuilder env(NSPEnv env) {
        IdCardBuilderParams params = this.params.copy();
        params.env = env;
        return new IdCardBuilder(params);
    }

    /**
     * Specify the CPR number of the user
     * 
     * @param cpr
     *            The CPR number
     * @return A new immutable builder instance that encapsulates the supplied parameter
     */
    public IdCardBuilder cpr(String cpr) {
        IdCardBuilderParams params = this.params.copy();
        params.cpr = cpr;
        return new IdCardBuilder(params);
    }

    /**
     * Specify the (moces/voces/foces) {@link CertAndKey} (certificate keypair) of the user or system that IdCards should identify.
     * 
     * @param certAndKey
     *            The keypair
     * @return A new immutable builder instance that encapsulates the supplied parameter
     */
    public IdCardBuilder certAndKey(CertAndKey certAndKey) {
        IdCardBuilderParams params = this.params.copy();
        params.certAndKey = certAndKey;
        return new IdCardBuilder(params);
    }

    /**
     * Specify email
     * 
     * @param email
     * @return A new immutable builder instance that encapsulates the supplied parameter
     */
    public IdCardBuilder email(String email) {
        IdCardBuilderParams params = this.params.copy();
        params.email = email;
        return new IdCardBuilder(params);
    }

    /**
     * Specify role
     * 
     * @param role
     * @return A new immutable builder instance that encapsulates the supplied parameter
     */
    public IdCardBuilder role(String role) {
        IdCardBuilderParams params = this.params.copy();
        params.role = role;
        return new IdCardBuilder(params);
    }

    /**
     * Specify occupation
     * 
     * @param occupation
     * @return A new immutable builder instance that encapsulates the supplied parameter
     */
    public IdCardBuilder occupation(String occupation) {
        IdCardBuilderParams params = this.params.copy();
        params.occupation = occupation;
        return new IdCardBuilder(params);
    }

    /**
     * Specify authorization code of the user
     * 
     * @param authorizationCode
     * @return A new immutable builder instance that encapsulates the supplied parameter
     */
    public IdCardBuilder authorizationCode(String authorizationCode) {
        IdCardBuilderParams params = this.params.copy();
        params.authorizationCode = authorizationCode;
        return new IdCardBuilder(params);
    }

    /**
     * Specify system name
     * 
     * @param systemName
     * @return A new immutable builder instance that encapsulates the supplied parameter
     */
    public IdCardBuilder systemName(String systemName) {
        IdCardBuilderParams params = this.params.copy();
        params.systemName = systemName;
        return new IdCardBuilder(params);
    }

    /**
     * Build IdCard from a {@link org.w3c.dom.Element} representation of the assertion (XML)
     * 
     * @param assertion
     * @return A new immutable builder instance that encapsulates the supplied parameter
     */
    public IdCardBuilder assertion(Element assertion) {
        IdCardBuilderParams params = this.params.copy();
        params.assertion = assertion;
        return new IdCardBuilder(params);
    }

    /**
     * @deprecated Renamed to {@link IdCardBuilder#fromXml} for consistency with other builders
     * @param xml
     * @return
     */
    public IdCardBuilder xml(String xml) {
        return fromXml(xml);
    }

    /**
     * Built IdCard from an XML String
     * 
     * @param xml
     *            The XML
     * @return A new immutable builder instance that encapsulates the supplied parameter
     */
    public IdCardBuilder fromXml(String xml) {
        IdCardBuilderParams params = this.params.copy();
        params.xml = xml;
        return new IdCardBuilder(params);
    }

    /**
     * If parameter is true, issue a legacy DGWS 1.0 IdCard (default is DGWS 1.0.1). Ignored if used in combination
     * with {@link IdCardBuilder#fromXml} or {@link IdCardBuilder#assertion}
     * 
     * @param useLegacyDGWS_1_0 If true use DGWS 1.0, otherwise DGWS 1.0.1
     * @return A new immutable builder instance that encapsulates the supplied parameter
     */
    public IdCardBuilder uselegacyDGWS_1_0(boolean useLegacyDGWS_1_0) {
        IdCardBuilderParams params = this.params.copy();
        params.useLegacyDGWS_1_0 = useLegacyDGWS_1_0;
        return new IdCardBuilder(params);
    }

    /**
     * Build IDCard from supplied parameters. If the builder is initialized from an assertion element or XML String, the type of IDCard will be autodetected (user
     * or system).
     * 
     * @return A {@link UserIdCard} or {@link SystemIdCard} dependending the attributes of the supplied XML
     * @throws IOException
     * @throws KeyStoreException
     * @throws NoSuchAlgorithmException
     * @throws CertificateException
     * @throws UnrecoverableKeyException
     * @throws SAXException
     * @throws ParserConfigurationException
     */
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

    /**
     * Built a {@link UserIdCard} from the supplied parameters.
     * 
     * @return a {@link UserIdCard}
     * @throws IOException
     * @throws KeyStoreException
     * @throws NoSuchAlgorithmException
     * @throws CertificateException
     * @throws UnrecoverableKeyException
     * @throws SAXException
     * @throws ParserConfigurationException
     */
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
            idCard = new UserIdCard(params.env, params.useLegacyDGWS_1_0, params.cpr, params.certAndKey.certificate,
                    params.certAndKey.privateKey, params.email, params.role, params.occupation,
                    params.authorizationCode,
                    params.systemName);
        }

        return idCard;
    }

    /**
     * Built a {@link SystemIdCard} from the supplied parameters.
     * 
     * @return A {@link SystemIdCard}
     * @throws IOException
     * @throws KeyStoreException
     * @throws NoSuchAlgorithmException
     * @throws CertificateException
     * @throws UnrecoverableKeyException
     * @throws SAXException
     * @throws ParserConfigurationException
     */
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
            idCard = new SystemIdCard(params.env, params.useLegacyDGWS_1_0, params.certAndKey.certificate, params.certAndKey.privateKey, params.systemName);
        }

        return idCard;
    }
}