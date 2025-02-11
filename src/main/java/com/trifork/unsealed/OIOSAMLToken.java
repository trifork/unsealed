package com.trifork.unsealed;

import static com.trifork.unsealed.SamlUtil.getSamlAttribute;
import static com.trifork.unsealed.XmlUtil.appendChild;
import static com.trifork.unsealed.XmlUtil.declareNamespaces;
import static com.trifork.unsealed.XmlUtil.getChild;
import static com.trifork.unsealed.XmlUtil.getTextChild;
import static com.trifork.unsealed.XmlUtil.setAttribute;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.time.ZonedDateTime;
import java.util.UUID;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.xml.crypto.MarshalException;
import javax.xml.crypto.dsig.XMLSignatureException;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.xpath.XPathExpressionException;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.xml.sax.SAXException;

public class OIOSAMLToken {
    public static final String DEFAULT_TOKEN_TO_IDCARD_ENDPOINT = "/sts/services/OIOSaml2Sosi";

    public static final String ASSURANCE_LEVEL = "dk:gov:saml:attribute:AssuranceLevel";

    protected Element assertion;
    protected NSPEnv env;
    protected Key privateKey;
    protected X509Certificate certificate;
    protected boolean encrypted;

    public OIOSAMLToken(NSPEnv env, X509Certificate certificate, Key privateKey,
            boolean encrypted, String xml) throws ParserConfigurationException, SAXException, IOException {

        this(env, certificate, privateKey, parseAssertion(xml), encrypted);
    }

    public OIOSAMLToken(NSPEnv env, X509Certificate certificate, Key privateKey, Element assertion,
            boolean encrypted) {
        this.env = env;
        this.privateKey = privateKey;
        this.certificate = certificate;
        this.assertion = assertion;
        this.encrypted = encrypted;
    }

    private static Element parseAssertion(String xml) throws ParserConfigurationException, SAXException, IOException {
        DocumentBuilder docBuilder = XmlUtil.getDocBuilder();
        Document doc = docBuilder.parse(new ByteArrayInputStream(xml.getBytes(StandardCharsets.UTF_8)));

        return doc.getDocumentElement();
    }

    public IdCard exchangeToIdCard(String itSystemName)
            throws ParserConfigurationException, IOException, InterruptedException,
            NoSuchAlgorithmException, InvalidAlgorithmParameterException, MarshalException, XMLSignatureException,
            SAXException, XPathExpressionException, STSInvocationException {
        return exchangeToIdCard(itSystemName, null, null);
    }

    public IdCard exchangeToIdCard(String itSystemName, String authorisationCode, String role)
            throws ParserConfigurationException, IOException, InterruptedException,
            NoSuchAlgorithmException, InvalidAlgorithmParameterException, MarshalException, XMLSignatureException,
            SAXException, XPathExpressionException, STSInvocationException {

        System.setProperty("com.sun.org.apache.xml.internal.security.ignoreLineBreaks", "true");

        if (role == null) {
            role = "urn:dk:healthcare:no-role";
        }

        String nameIdValue = getUID();
        String userSurName = getSurName();
        String commonName = getCommonName();
        String userGivenName;
        if (commonName.endsWith(userSurName)) {
            userGivenName = commonName.substring(0, commonName.length() - userSurName.length()).trim();
        } else {
            userGivenName = "";
        }

        Element request = createSAMLTokenToIdCardRequest(assertion, itSystemName, nameIdValue, userSurName,
                userGivenName, authorisationCode, role);

        Document doc = request.getOwnerDocument();

        SignatureUtil.sign(doc.getElementById("security"), null,
                new String[] { "#messageID", "#action", "#ts", "#body" }, null, certificate, privateKey, false);

        Element response = WSHelper.post(request, env.getStsBaseUrl() + DEFAULT_TOKEN_TO_IDCARD_ENDPOINT,
                "http://docs.oasis-open.org/ws-sx/ws-trust/200512/RST/Issue");

        XPathContext xpath = new XPathContext(response.getOwnerDocument());

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

    public boolean isEncrypted() {
        return encrypted;
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
    public ZonedDateTime getNotBefore() {
        Element attributeStatement = getChild(assertion, NsPrefixes.saml, "Conditions");
        String notBefore = attributeStatement.getAttribute("NotBefore");

        ZonedDateTime date = ZonedDateTime.parse(notBefore);
        return date;
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
    public ZonedDateTime getNotOnOrAfter() {
        Element attributeStatement = getChild(assertion, NsPrefixes.saml, "Conditions");
        String notOnOrAfter = attributeStatement.getAttribute("NotOnOrAfter");

        ZonedDateTime date = ZonedDateTime.parse(notOnOrAfter);
        return date;
    }

    public String getCommonName() {
        return getSamlAttribute(getAttributeStatement(), isOiosaml2() ? OIOSAML2Constants.COMMON_NAME : OIOSAML3Constants.COMMON_NAME);
    }

    private Element getAttributeStatement() {
        return getChild(assertion, NsPrefixes.saml, "AttributeStatement");
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
        return getSamlAttribute(getAttributeStatement(), isOiosaml2() ? OIOSAML2Constants.CPR_NUMBER : OIOSAML3Constants.CPR_NUMBER);
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
        return getSamlAttribute(getAttributeStatement(), isOiosaml2() ? OIOSAML2Constants.CVR_NUMBER : OIOSAML3Constants.CVR_NUMBER);
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
        return getSamlAttribute(getAttributeStatement(), isOiosaml2() ? OIOSAML2Constants.EMAIL : OIOSAML3Constants.EMAIL);
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
        return getSamlAttribute(getAttributeStatement(), isOiosaml2() ? OIOSAML2Constants.ORGANIZATION_NAME : OIOSAML3Constants.ORGANIZATION_NAME);
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
        return getSamlAttribute(getAttributeStatement(), isOiosaml2() ? OIOSAML2Constants.SURNAME : OIOSAML3Constants.SURNAME);
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
        boolean encrypted = "EncryptedAssertion".equals(assertion.getLocalName());

        if (encrypted) {
            throw new IllegalStateException("EncryptedAssertion not yet decrypted - unable to determine spec version");
        }

        Element attributeStatement = getAttributeStatement();

        String oiosaml2SpecVersion = getSamlAttribute(attributeStatement, OIOSAML2Constants.SPEC_VERSION);

        if (oiosaml2SpecVersion != null) {
            if (OIOSAML2Constants.OIOSAML2_VERSION_NAME.equals(oiosaml2SpecVersion)) {
                // We guessed right above, so just return the OIOSAML2Token we created above
                return oiosaml2SpecVersion;
            }
            throw new IllegalArgumentException("Unexpected spec version, " + OIOSAML2Constants.SPEC_VERSION + "=" + oiosaml2SpecVersion);
        }

        String oiosaml3SpecVersion = getSamlAttribute(attributeStatement, OIOSAML3Constants.SPEC_VERSION);
        if (oiosaml3SpecVersion != null) {
            if (OIOSAML3Constants.OIOSAML_H_3_VERSION_NAME.equals(oiosaml3SpecVersion) || OIOSAML3Constants.OIOSAML3_VERSION_NAME.equals(oiosaml3SpecVersion)) {
                return oiosaml3SpecVersion;
            }
            throw new IllegalArgumentException("Unexpected spec version, " + OIOSAML3Constants.SPEC_VERSION + "=" + oiosaml3SpecVersion);
        }

        throw new IllegalStateException("Unable to determine spec version, found neither OIOSAML2 nor OIOSAML3 spec version attribute");
    }

    public String getUID() {
        if (isOiosaml2()) {
            return getSamlAttribute(getAttributeStatement(), OIOSAML2Constants.UID);
        }
        throw new UnsupportedOperationException("Not supported for OIOSAML3 assertions");
    }

    protected Object getCprUuid() {
        if (isOiosaml2()) {
            throw new UnsupportedOperationException("Not supported for OIOSAML2 assertions");
        }
        return getSamlAttribute(getAttributeStatement(), OIOSAML3Constants.CPR_UUID);
    }

    protected Object getProfUuid() {
        if (isOiosaml2()) {
            throw new UnsupportedOperationException("Not supported for OIOSAML2 assertions");
        }
        return getSamlAttribute(getAttributeStatement(), OIOSAML3Constants.PROF_UUID);
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
        String assuranceLevel = getSamlAttribute(getAttributeStatement(), ASSURANCE_LEVEL);

        return assuranceLevel;
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
        Element attributeStatement = getChild(assertion, NsPrefixes.saml, "Conditions");
        Element audienceRestriction = getChild(attributeStatement, NsPrefixes.saml, "AudienceRestriction");
        String audience = getTextChild(audienceRestriction, NsPrefixes.saml, "Audience");

        return audience;
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
    public ZonedDateTime getUserAuthenticationInstant() {

        Element authnStatement = getChild(assertion, NsPrefixes.saml, "AuthnStatement");
        String authnInstant = authnStatement.getAttribute("AuthnInstant");

        ZonedDateTime date = ZonedDateTime.parse(authnInstant);
        return date;
    }

    /**
     * Invoke this method to verify the validity of the
     * <code>AbstractOIOSamlToken</code> against the {@link #getNotBefore()} and
     * {@link #getNotOnOrAfter()} values.<br>
     * 
     * @throws ValidationException
     *
     */
    public void validateTimes() throws ValidationException {
        validateTimes(0);
    }

    /**
     * Invoke this method to verify the validity of the
     * <code>AbstractOIOSamlToken</code> against the {@link #getNotBefore()} and
     * {@link #getNotOnOrAfter()} values.<br>
     *
     * @param allowedDriftInSeconds
     *            the amount of clock drift to allow in
     *            milliseconds
     * @throws ValidationException
     *
     */
    public void validateTimes(long allowedDriftInSeconds) throws ValidationException {
        ZonedDateTime now = ZonedDateTime.now();

        if (now.plusSeconds(allowedDriftInSeconds).isBefore(getNotBefore())) {
            throw new ValidationException("Assertion is not yet valid (" + getNotBefore() + " < " + now + ")");
        }

        if (now.minusSeconds(allowedDriftInSeconds).isAfter(getNotOnOrAfter())) {
            throw new ValidationException("Assertion is no longer valid (" + getNotBefore() + " > " + now + ")");
        }
    }

    public void decrypt() throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException,
            InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException, SAXException, IOException,
            ParserConfigurationException {

        if (!encrypted) {
            throw new IllegalStateException("Assertion is not encrypted");
        }

        Element encryptedData = getChild(assertion, NsPrefixes.xenc, "EncryptedData");
        Element encryptionMethod = getChild(encryptedData, NsPrefixes.xenc, "EncryptionMethod");
        String encryptionAlgo = encryptionMethod.getAttribute("Algorithm");
        Element keyInfo = getChild(encryptedData, NsPrefixes.ds, "KeyInfo");
        Element encryptedKey = getChild(keyInfo, NsPrefixes.xenc, "EncryptedKey");
        Element encryptedKeyEncryptionMethod = getChild(encryptedKey, NsPrefixes.xenc, "EncryptionMethod");
        String encryptedKeyEncryptionAlgo = encryptedKeyEncryptionMethod.getAttribute("Algorithm");

        Key decryptedKey = XmlUtil.decryptKey(privateKey, encryptedKey, encryptedKeyEncryptionAlgo, encryptionAlgo);

        String decrypted = XmlUtil.decrypt(decryptedKey, encryptedData, encryptionAlgo);

        assertion = XmlUtil.getDocBuilder().parse(new ByteArrayInputStream(decrypted.getBytes(StandardCharsets.UTF_8))).getDocumentElement();
    }

    private boolean isOiosaml2() {
        return OIOSAML2Constants.OIOSAML2_VERSION_NAME.equals(getSpecVersion());
    }

    private Element createSAMLTokenToIdCardRequest(Element samlToken, String itSystemName, String nameIdValue,
            String userSurName, String userGivenName, String authorisationCode, String role)
            throws ParserConfigurationException {

        DocumentBuilder docBuilder = XmlUtil.getDocBuilder();
        Document doc = docBuilder.newDocument();

        Element envelope = appendChild(doc, NsPrefixes.soap, "Envelope");

        declareNamespaces(envelope, NsPrefixes.soap, NsPrefixes.xsi, NsPrefixes.wsse, NsPrefixes.wst, NsPrefixes.wsa,
                NsPrefixes.wsu, NsPrefixes.xsd);

        Element soapHeader = appendChild(envelope, NsPrefixes.soap, "Header");

        Element action = appendChild(soapHeader, NsPrefixes.wsa, "Action",
                "http://docs.oasis-open.org/ws-sx/ws-trust/200512/RST/Issue");
        setAttribute(action, NsPrefixes.wsu, "Id", "action", true);

        String msgId = "urn:uuid:" + UUID.randomUUID().toString();
        Element messageID = appendChild(soapHeader, NsPrefixes.wsa, "MessageID", msgId);
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

        appendSenderVouchesAssertion(actAs, itSystemName, nameIdValue, userSurName, userGivenName, authorisationCode,
                role);

        appendChild(appendChild(appendChild(requestSecurityToken, NsPrefixes.wsp, "AppliesTo"), NsPrefixes.wsa,
                "EndpointReference"), NsPrefixes.wsa, "Address", "http://sosi.dk");

        return envelope;
    }

    private void appendSenderVouchesAssertion(Element parent, String itSystemName, String nameIdValue,
            String userSurName, String userGivenName, String authorisationCode, String role) {

        Element assertion = appendChild(parent, NsPrefixes.saml, "Assertion");

        declareNamespaces(assertion, NsPrefixes.saml);

        assertion.setAttribute("IssueInstant", XmlUtil.ISO_WITH_MILLIS_FORMATTER.format(Instant.now()));
        assertion.setAttribute("Version", "2.0");
        assertion.setAttribute("ID", "sva");

        appendChild(assertion, NsPrefixes.saml, "Issuer", itSystemName);

        Element subject = appendChild(assertion, NsPrefixes.saml, "Subject");
        Element nameId = appendChild(subject, NsPrefixes.saml, "NameID", nameIdValue);
        nameId.setAttribute("Format", "urn:oasis:names:tc:SAML:1.1:nameid-format:X509SubjectName");

        Element subjectConfirmation = appendChild(subject, NsPrefixes.saml, "SubjectConfirmation");
        subjectConfirmation.setAttribute("Method", "urn:oasis:names:tc:SAML:2.0:cm:sender-vouches");

        Element attributeStatement = appendChild(assertion, NsPrefixes.saml, "saml:AttributeStatement");
        SamlUtil.addSamlAttribute(attributeStatement, "dk:healthcare:saml:attribute:UserEducationCode",
                role);
        SamlUtil.addSamlAttribute(attributeStatement, "dk:healthcare:saml:attribute:UserAuthorizationCode",
                authorisationCode);
        SamlUtil.addSamlAttribute(attributeStatement, "dk:healthcare:saml:attribute:UserSurName", userSurName);
        SamlUtil.addSamlAttribute(attributeStatement, "dk:healthcare:saml:attribute:ITSystemName", itSystemName);
        SamlUtil.addSamlAttribute(attributeStatement, "dk:healthcare:saml:attribute:UserGivenName", userGivenName);
    }

}