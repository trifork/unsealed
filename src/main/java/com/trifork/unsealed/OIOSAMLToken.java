package com.trifork.unsealed;

import static com.trifork.unsealed.XmlUtil.appendChild;
import static com.trifork.unsealed.XmlUtil.declareNamespaces;
import static com.trifork.unsealed.XmlUtil.setAttribute;
import static java.util.logging.Level.FINE;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.Date;
import java.util.UUID;
import java.util.logging.Logger;

import javax.xml.crypto.MarshalException;
import javax.xml.crypto.dsig.XMLSignatureException;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.xpath.XPathExpressionException;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.xml.sax.SAXException;

public class OIOSAMLToken {
    private static final Logger logger = Logger.getLogger(OIOSAMLToken.class.getName());
    public static final String DEFAULT_TOKEN_TO_IDCARD_ENDPOINT = "/sts/services/OIOSaml2Sosi";

    static final String COMMON_NAME = "urn:oid:2.5.4.3";
    static final String SURNAME = "urn:oid:2.5.4.4";
    static final String CPR_NUMBER = "dk:gov:saml:attribute:CprNumberIdentifier";
    static final String CVR_NUMBER = "dk:gov:saml:attribute:CvrNumberIdentifier";
    static final String RID_NUMBER = "dk:gov:saml:attribute:RidNumberIdentifier";
    static final String PID_NUMBER = "dk:gov:saml:attribute:PidNumberIdentifier";

    static final String PRIVILEGES_INTERMEDIATE = "dk:gov:saml:attribute:Privileges_intermediate";
    static final String THROUGH_PROCURATION_BY = "urn:dk:gov:saml:actThroughProcurationBy:cprNumberIdentifier";

    static final String EMAIL = "urn:oid:0.9.2342.19200300.100.1.3";
    static final String ORGANIZATION_NAME = "urn:oid:2.5.4.10";
    static final String USER_CERTIFICATE = "urn:oid:1.3.6.1.4.1.1466.115.121.1.8";
    static final String CERTIFICATE_ISSUER = "urn:oid:2.5.29.29";
    static final String IS_YOUTH_CERT = "dk:gov:saml:attribute:IsYouthCert";
    static final String ASSURANCE_LEVEL = "dk:gov:saml:attribute:AssuranceLevel";
    static final String SPEC_VERSION = "dk:gov:saml:attribute:SpecVer";
    static final String CERTIFICATE_SERIAL = "urn:oid:2.5.4.5";
    static final String UID = "urn:oid:0.9.2342.19200300.100.1.1";
    static final String DISCOVERY_EPR = "urn:liberty:disco:2006-08:DiscoveryEPR";

    static final String SURNAME_FRIENDLY = "surName";
    static final String COMMON_NAME_FRIENDLY = "CommonName";
    static final String EMAIL_FRIENDLY = "email";
    static final String ORGANIZATION_NAME_FRIENDLY = "organizationName";
    static final String CERTIFICATE_SERIAL_FRIENDLY = "serialNumber";
    static final String UID_FRIENDLY = "Uid";

    private Element assertion;
    private NSPEnv env;
    private Key privateKey;
    private X509Certificate certificate;
    private String xml;

    public OIOSAMLToken(NSPEnv env, Key privateKey, X509Certificate certificate, Element assertion,
            boolean encryptedAssertion, String xml) {
        this.env = env;
        this.privateKey = privateKey;
        this.certificate = certificate;
        this.assertion = assertion;
        this.xml = xml;
    }

    public IdCard exchangeToIdCard() throws ParserConfigurationException, IOException, InterruptedException,
            NoSuchAlgorithmException, InvalidAlgorithmParameterException, MarshalException, XMLSignatureException,
            SAXException, XPathExpressionException {

        System.setProperty("com.sun.org.apache.xml.internal.security.ignoreLineBreaks", "true");

        DocumentBuilder docBuilder = IdCard.getDocBuilder();
        Element samlToken = docBuilder.parse(new ByteArrayInputStream(xml.getBytes(StandardCharsets.UTF_8)))
                .getDocumentElement();

        Element request = createSAMLTokenToIdCardRequest(samlToken);

        Document doc = request.getOwnerDocument();

        SignatureUtil.sign(doc.getElementById("security"), null,
                new String[] { "#messageID", "#action", "#ts", "#body" }, null, certificate, privateKey, false);

        logger.log(FINE, "Request body: " + XmlUtil.node2String(request, false, false));

        String response = WSHelper.post(XmlUtil.node2String(request, false, false),
                env.getStsBaseUrl() + DEFAULT_TOKEN_TO_IDCARD_ENDPOINT,
                "http://docs.oasis-open.org/ws-sx/ws-trust/200512/RST/Issue");

        logger.log(FINE, "Response: " + response);

        Element envelope = docBuilder.parse(new ByteArrayInputStream(response.getBytes(StandardCharsets.UTF_8)))
                .getDocumentElement();

        XPathContext xpath = new XPathContext(envelope.getOwnerDocument());

        String REQUEST_SECURITY_TOKEN_RESPONSE_XPATH = "/" 
                + NsPrefixes.soap.name() + ":Envelope/"
                + NsPrefixes.soap.name() + ":Body/" 
                + NsPrefixes.wst13.name() + ":RequestSecurityTokenResponseCollection/" 
                + NsPrefixes.wst13.name() + ":RequestSecurityTokenResponse/"
                + NsPrefixes.wst13.name() + ":RequestedSecurityToken/" 
                + NsPrefixes.saml.name() + ":Assertion";

        Element assertion = xpath.findElement(REQUEST_SECURITY_TOKEN_RESPONSE_XPATH);

        IdCard idCard = new UserIdCard(env, assertion);

        return idCard;
    }

    public Element getAssertion() {
        return assertion;
    }

    public String getCommonName() {
        // Element commonNameElm = getAttributeElement(OIOSAMLAttributes.COMMON_NAME);
        // if(commonNameElm == null) {
        // throw new ModelException("Mandatory 'commonName' SAML attribute
        // (urn:oid:2.5.4.3) is missing");
        // }
        // return commonNameElm.getTextContent().trim();
        return null;
    }

    /**
     * Extract the <code>dk:gov:saml:attribute:CprNumberIdentifier</code> value from
     * the DOM.<br>
     *
     * <pre>
     *     &lt;saml:Attribute NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic"
     *       Name="dk:gov:saml:attribute:CprNumberIdentifier"&gt;
     *       &lt;saml:AttributeValue xsi:type="xs:string"&gt;2702681273&lt;/saml:AttributeValue&gt;
     *     &lt;/saml:Attribute&gt;
     * </pre>
     *
     * @return The value of the
     *         <code>dk:gov:saml:attribute:CprNumberIdentifier</code> tag.
     */
    public String getCpr() {
        // return getAttribute(OIOSAMLAttributes.CPR_NUMBER);
        return null;
    }

    /**
     * Extract the <code>dk:gov:saml:attribute:CvrNumberIdentifier</code> value from
     * the DOM.<br>
     *
     * <pre>
     *     &lt;saml:Attribute NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic"
     *         Name="dk:gov:saml:attribute:CvrNumberIdentifier"&gt;
     *         &lt;saml:AttributeValue xsi:type="xs:string"&gt;20688092&lt;/saml:AttributeValue&gt;
     *       &lt;/saml:Attribute&gt;
     * </pre>
     *
     * @return The value of the
     *         <code>dk:gov:saml:attribute:CvrNumberIdentifier</code> tag.
     */
    public String getCvrNumberIdentifier() {
        // return getAttribute(OIOSAMLAttributes.CVR_NUMBER);
        return null;
    }

    /**
     * Extract the <code>urn:oid:0.9.2342.19200300.100.1.3</code>/email value from
     * the DOM.<br>
     *
     * <pre>
     *     &lt;saml:Attribute NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic"
     *       Name="urn:oid:0.9.2342.19200300.100.1.3" FriendlyName="email"&gt;
     *       &lt;saml:AttributeValue xsi:type="xs:string"&gt;jens@email.dk&lt;/saml:AttributeValue&gt;
     *     &lt;/saml:Attribute&gt;
     * </pre>
     *
     * @return The value of the <code>urn:oid:0.9.2342.19200300.100.1.3</code>/email
     *         tag.
     */
    public String getEmail() {
        // Element emailElm = getAttributeElement(OIOSAMLAttributes.EMAIL);
        // if(emailElm == null) {
        // throw new ModelException("Mandatory 'email' SAML attribute
        // (urn:oid:0.9.2342.19200300.100.1.3) is missing");
        // }
        // return emailElm.getTextContent().trim();
        return null;
    }

    /**
     * Extract the <code>saml:Conditions#NotBefore</code> value from the DOM.<br>
     *
     * <pre>
     *   &lt;saml:Conditions NotBefore="2011-07-23T15:32:12Z" ... &gt;
     *      ...
     *   &lt;/saml:Conditions&gt;
     * </pre>
     *
     * @return The value of the <code>saml:Conditions#NotBefore</code> tag.
     */
    public Date getNotBefore() {
        // Element ac = getTag(SAMLTags.assertion, SAMLTags.conditions);
        // return convertToDate(ac, SAMLAttributes.NOT_BEFORE);

        return null;
    }

    /**
     * Extract the <code>saml:Conditions#NotOnOrAfter</code> value from the DOM.<br>
     *
     * <pre>
     *   &lt;saml:Conditions ... NotOnOrAfter="2011-07-23T15:37:12Z" &gt;
     *      ...
     *   &lt;/saml:Conditions&gt;
     * </pre>
     *
     * @return The value of the <code>saml:Conditions#NotOnOrAfter</code> tag.
     */
    public Date getNotOnOrAfter() {
        // Element ac = getTag(SAMLTags.assertion, SAMLTags.conditions);
        // return convertToDate(ac, SAMLAttributes.NOT_ON_OR_AFTER);
        return null;
    }

    /**
     * Extract the <code>urn:oid:2.5.4.10</code>/organizationName value from the
     * token.<br>
     *
     * <pre>
     *     &lt;saml:Attribute NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic" Name="urn:oid:2.5.4.10"
     *       FriendlyName="organizationName"&gt;
     *       &lt;saml:AttributeValue xsi:type="xs:string"&gt;Lægehuset på bakken&lt;/saml:AttributeValue&gt;
     *     &lt;/saml:Attribute&gt;
     * </pre>
     *
     * @return The value of the <code>urn:oid:2.5.4.10</code>/organizationName tag.
     */
    public String getOrganizationName() {
        // return getAttribute(OIOSAMLAttributes.ORGANIZATION_NAME);
        return null;
    }

    /**
     * Extract the <code>urn:oid:2.5.4.4</code>/surName value from the token.<br>
     *
     * <pre>
     *     &lt;saml:Attribute NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic" Name="urn:oid:2.5.4.4"
     *       FriendlyName="surName"&gt;
     *       &lt;saml:AttributeValue xsi:type="xs:string"&gt;Poulsen&lt;/saml:AttributeValue&gt;
     *     &lt;/saml:Attribute&gt;
     * </pre>
     *
     * @return The value of the <code>urn:oid:2.5.4.4</code>/surName tag.
     */
    public String getSurName() {
        // Element surNameElm = getAttributeElement(OIOSAMLAttributes.SURNAME);
        // if(surNameElm == null) {
        // throw new ModelException("Mandatory 'surName' SAML attribute
        // (urn:oid:2.5.4.4) is missing");
        // }
        // return surNameElm.getTextContent().trim();
        return null;
    }

    /**
     * Extract the <code>dk:gov:saml:attribute:AssuranceLevel</code> value from the
     * token.<br>
     *
     * <pre>
     *     &lt;saml:Attribute NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic" Name="dk:gov:saml:attribute:AssuranceLevel"&gt;
     *       &lt;saml:AttributeValue xsi:type="xs:string"&gt;3&lt;/saml:AttributeValue&gt;
     *     &lt;/saml:Attribute&gt;
     * </pre>
     *
     * @return The value of the <code>dk:gov:saml:attribute:AssuranceLevel</code>
     *         tag.
     */
    public String getAssuranceLevel() {
        // Element assuranceLevelElm =
        // getAttributeElement(OIOSAMLAttributes.ASSURANCE_LEVEL);
        // if(assuranceLevelElm == null) {
        // throw new ModelException("Mandatory 'assuranceLevel' SAML attribute
        // (dk:gov:saml:attribute:AssuranceLevel) is missing");
        // }
        // return assuranceLevelElm.getTextContent().trim();
        return null;
    }

    /**
     * Extract the <code>dk:gov:saml:attribute:SpecVer</code> value from the
     * DOM.<br>
     *
     * <pre>
     *     &lt;saml:Attribute NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic" Name="dk:gov:saml:attribute:SpecVer"&gt;
     *       &lt;saml:AttributeValue xsi:type="xs:string"&gt;DK-SAML-2.0&lt;/saml:AttributeValue&gt;
     *     &lt;/saml:Attribute&gt;
     * </pre>
     *
     * @return The value of the <code>dk:gov:saml:attribute:SpecVer</code> tag.
     */
    public String getSpecVersion() {
        // Element specVersionElm = getAttributeElement(OIOSAMLAttributes.SPEC_VERSION);
        // if(specVersionElm == null) {
        // throw new ModelException("Mandatory 'specVersion' SAML attribute
        // (dk:gov:saml:attribute:SpecVer) is missing");
        // }
        // return specVersionElm.getTextContent().trim();
        return null;
    }

    /**
     * Extract the <code>saml:AudienceRestriction</code> value from the DOM.<br>
     *
     * <pre>
     *   &lt;saml:Conditions ... &gt;
     *      &lt;saml:AudienceRestriction&gt;http://fmk-online.dk&lt;/saml:AudienceRestriction&gt;
     *   &lt;/saml:Conditions&gt;
     * </pre>
     *
     * @return The value of the <code>saml:AudienceRestriction</code> tag.
     */
    public String getAudienceRestriction() {
        // Element ac = getTag(SAMLTags.assertion, SAMLTags.conditions,
        // SAMLTags.audienceRestriction);
        // if (ac == null) {
        // return null;
        // }
        // return ac.getTextContent().trim();
        return null;
    }

    /**
     * Extract the <code>AuthnInstant</code> value from the DOM, that is the time
     * the user originally authenticated herself.<br>
     *
     * <pre>
     *       &lt;saml:AuthnStatement AuthnInstant="2011-07-23T11:42:52Z"&gt;
     *          &lt;saml:AuthnContext&gt;
     *              &lt;saml:AuthnContextClassRef&gt;urn:oasis:names:tc:SAML:2.0:ac:classes:X509&lt;/saml:AuthnContextClassRef&gt;
     *          &lt;/saml:AuthnContext&gt;
     *       &lt;/saml:AuthnStatement&gt;
     * </pre>
     *
     * @return The value of the <code>AuthnInstant</code> attribute.
     */
    public Date getUserAuthenticationInstant() {
        // final Element auth = getTag(SAMLTags.assertion, SAMLTags.authnStatement);
        // return convertToDate(auth, SAMLAttributes.AUTHN_INSTANT);
        return null;
    }

    /**
     * Invoke this method to verify the validity of the
     * <code>AbstractOIOSamlToken</code> against the {@link #getNotBefore()} and
     * {@link #getNotOnOrAfter()} values.<br>
     *
     */
    public void validateTimestamp() {
        // validateTimestamp(0);
    }

    /**
     * Invoke this method to verify the validity of the
     * <code>AbstractOIOSamlToken</code> against the {@link #getNotBefore()} and
     * {@link #getNotOnOrAfter()} values.<br>
     *
     * @param allowedDriftInSeconds the amount of clock drift to allow in
     *                              milliseconds
     *
     */
    public void validateTimestamp(long allowedDriftInSeconds) {
        // if (allowedDriftInSeconds < 0) throw new
        // IllegalArgumentException("'allowedDriftInSeconds' must not be negative!");
        // Date now = new Date();
        // DateFormat format = XmlUtil.getDateFormat(true);

        // if (new Date(now.getTime() + allowedDriftInSeconds *
        // 1000).before(getNotBefore())) {
        // throw new ModelException("OIOSAML token is not valid yet - now: " +
        // format.format(now) +
        // ". OIOSAML token validity start: " + format.format(getNotBefore()) + ".
        // Allowed clock drift: " + allowedDriftInSeconds + " seconds");
        // }
        // if (!new Date(now.getTime() - allowedDriftInSeconds *
        // 1000).before(getNotOnOrAfter())) {
        // throw new ModelException("OIOSAML token no longer valid - now: " +
        // format.format(now) +
        // ". OIOSAML token validity end: " + format.format(getNotOnOrAfter()) + ".
        // Allowed clock drift: " + allowedDriftInSeconds + " seconds");
        // }

    }

    private Element createSAMLTokenToIdCardRequest(Element samlToken) throws ParserConfigurationException {

        DocumentBuilder docBuilder = IdCard.getDocBuilder();
        Document doc = docBuilder.newDocument();

        Element envelope = appendChild(doc, NsPrefixes.soap, "Envelope");

        // declareNamespaces(envelope, NsPrefixes.soap, NsPrefixes.ds, NsPrefixes.xsi,
        // NsPrefixes.wsse, NsPrefixes.wst,
        // NsPrefixes.wsa10, NsPrefixes.wsu, NsPrefixes.xsd);
        declareNamespaces(envelope, NsPrefixes.soap, NsPrefixes.xsi, NsPrefixes.wsse, NsPrefixes.wst, NsPrefixes.wsa10,
                NsPrefixes.wsu, NsPrefixes.xsd);

        Element soapHeader = appendChild(envelope, NsPrefixes.soap, "Header");

        Element action = appendChild(soapHeader, NsPrefixes.wsa10, "Action",
                "http://docs.oasis-open.org/ws-sx/ws-trust/200512/RST/Issue");
        setAttribute(action, NsPrefixes.wsu, "Id", "action", true);

        String msgId = "urn:uuid:" + UUID.randomUUID().toString();
        Element messageID = appendChild(soapHeader, NsPrefixes.wsa10, "MessageID", msgId);
        setAttribute(messageID, NsPrefixes.wsu, "Id", "messageID", true);

        Element security = appendChild(soapHeader, NsPrefixes.wsse, "Security");
        setAttribute(security, NsPrefixes.wsu, "Id", "security", true);
        security.setAttribute("mustUnderstand", "1");

        Element timestamp = appendChild(security, NsPrefixes.wsu, "Timestamp");
        setAttribute(timestamp, NsPrefixes.wsu, "Id", "ts", true);
        appendChild(timestamp, NsPrefixes.wsu, "Created", XmlUtil.ISO_WITH_MILLIS_FORMATTER.format(Instant.now()));

        Element soapBody = appendChild(envelope, NsPrefixes.soap, "Body");
        setAttribute(soapBody, NsPrefixes.wsu, "Id", "body", true);

        Element requestSecurityToken = appendChild(soapBody, NsPrefixes.wst13, "RequestSecurityToken");
        requestSecurityToken.setAttribute("Context", "urn:uuid:" + UUID.randomUUID().toString());
        appendChild(requestSecurityToken, NsPrefixes.wst13, "TokenType",
                "http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.1#SAMLV2.0");
        appendChild(requestSecurityToken, NsPrefixes.wst13, "RequestType",
                "http://docs.oasis-open.org/ws-sx/ws-trust/200512/Issue");

        Element actAs = appendChild(requestSecurityToken, NsPrefixes.wst14, "ActAs");
        actAs.appendChild(doc.importNode(samlToken, true));

        appendSenderVouchesAssertion(actAs);

        appendChild(appendChild(appendChild(requestSecurityToken, NsPrefixes.wsp, "AppliesTo"), NsPrefixes.wsa10,
                "EndpointReference"), NsPrefixes.wsa10, "Address", "http://sosi.dk");

        return envelope;
    }

    private void appendSenderVouchesAssertion(Element parent) {
        String nameIdValue = "CVR:20921897-RID:52723247";
        String userEducationCode = "doctor";
        String userAuthorizationCode = "J0184";
        String userSurName = "Larsen";
        String itSystemName = "FMK-online";
        String userGivenName = "Lars";

        Element assertion = appendChild(parent, NsPrefixes.saml, "Assertion");

        declareNamespaces(assertion, NsPrefixes.saml);

        assertion.setAttribute("IssueInstant", XmlUtil.ISO_WITH_MILLIS_FORMATTER.format(Instant.now()));
        assertion.setAttribute("Version", "2.0");
        assertion.setAttribute("ID", "sva");

        appendChild(assertion, NsPrefixes.saml, "Issuer", "FMK-online");

        Element subject = appendChild(assertion, NsPrefixes.saml, "Subject");
        Element nameId = appendChild(subject, NsPrefixes.saml, "NameID", nameIdValue);
        nameId.setAttribute("Format", "urn:oasis:names:tc:SAML:1.1:nameid-format:X509SubjectName");

        Element subjectConfirmation = appendChild(subject, NsPrefixes.saml, "SubjectConfirmation");
        subjectConfirmation.setAttribute("Method", "urn:oasis:names:tc:SAML:2.0:cm:sender-vouches");

        Element attributeStatement = appendChild(assertion, NsPrefixes.saml, "saml:AttributeStatement");
        SamlUtil.addSamlAttribute(attributeStatement, "dk:healthcare:saml:attribute:UserEducationCode",
                userEducationCode);
        SamlUtil.addSamlAttribute(attributeStatement, "dk:healthcare:saml:attribute:UserAuthorizationCode",
                userAuthorizationCode);
        SamlUtil.addSamlAttribute(attributeStatement, "dk:healthcare:saml:attribute:UserSurName", userSurName);
        SamlUtil.addSamlAttribute(attributeStatement, "dk:healthcare:saml:attribute:ITSystemName", itSystemName);
        SamlUtil.addSamlAttribute(attributeStatement, "dk:healthcare:saml:attribute:UserGivenName", userGivenName);
    }
}