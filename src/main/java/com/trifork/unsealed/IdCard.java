package com.trifork.unsealed;

import static com.trifork.unsealed.XmlUtil.ISO_WITHOUT_MILLIS_FORMATTER;
import static com.trifork.unsealed.XmlUtil.appendChild;
import static com.trifork.unsealed.XmlUtil.getChild;
import static com.trifork.unsealed.XmlUtil.getTextChild;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.time.ZonedDateTime;
import java.time.temporal.ChronoUnit;
import java.util.UUID;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.xml.crypto.MarshalException;
import javax.xml.crypto.dsig.XMLSignatureException;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.xml.sax.SAXException;

public abstract class IdCard {
    public static final String DEFAULT_SIGN_IDCARD_ENDPOINT = "/sts/services/NewSecurityTokenService";
    public static final String LEGACY_SIGN_IDCARD_ENDPOINT = "/sts/services/SecurityTokenService";
    public static final String DEFAULT_IDCARD_TO_TOKEN_ENDPOINT = "/sts/services/Sosi2OIOSaml";

    protected static final String SOSI_IDCARD_TYPE = "sosi:IDCardType";
    protected static final String SOSI_AUTH_LEVEL = "sosi:AuthenticationLevel";
    protected static final String SOSI_IDCARD_VERSION = "sosi:IDCardVersion";
    protected static final String SOSI_IDCARD_ID = "sosi:IDCardID";
    protected static final String MEDCOM_IT_SYSTEM_NAME = "medcom:ITSystemName";
    protected static final String MEDCOM_CARE_PROVIDER_ID = "medcom:CareProviderID";
    protected static final String MEDCOM_CARE_PROVIDER_NAME = "medcom:CareProviderName";

    private static final int NOT_BEFORE_ALLOWED_SLACK = 5;
    private static final String IDCARD_TO_TOKEN_RESPONSE_XPATH = "/" + NsPrefixes.soap.name() + ":Envelope/"
            + NsPrefixes.soap.name() + ":Body/" + NsPrefixes.wst13.name() + ":RequestSecurityTokenResponseCollection/"
            + NsPrefixes.wst13.name() + ":RequestSecurityTokenResponse/" + NsPrefixes.wst13.name() + ":RequestedSecurityToken";

    private NSPEnv env;
    protected String cvr;
    protected String organisation;
    private X509Certificate certificate;
    private Key privateKey;
    private String systemName;
    protected String idCardType;
    protected String itSystemName;
    protected String careProviderId;
    protected String careProviderIdNameFormat;
    protected String careProviderName;
    protected boolean useLegacyDGWS_1_0;

    protected Element signedIdCard;

    private Element assertion;

    private Element encryptedAssertion;
    private int authLevel;
    private String dgwsVersion;
    private String idCardId;

    protected IdCard(NSPEnv env, boolean useLegacyDGWS_1_0, X509Certificate certificate, Key privateKey, String systemName) {
        this.env = env;
        this.useLegacyDGWS_1_0 = useLegacyDGWS_1_0;
        this.certificate = certificate;
        this.privateKey = privateKey;
        this.systemName = systemName;
    }

    IdCard(NSPEnv env, Element signedIdCard) {
        this.env = env;
        this.signedIdCard = signedIdCard;

        extractSamlAttributes(signedIdCard);
    }

    /**
     * Get the IT System Name of this IDCard
     * 
     * @return The value of the SAML attribute named "medcom:ITSystemName"
     */
    public String getItSystemName() {
        return itSystemName;
    }

    /**
     * Get the authentication level of this IDCard
     * 
     * @return The value of the SAML attribute named "sosi:AuthenticationLevel"
     */
    public int getAuthLevel() {
        return authLevel;
    }

    /**
     * Get the DGWS-version of this IDCard
     * 
     * @return The value of the SAML attribute named "sosi:IDCardVersion"
     */
    public String getDGWSVersion() {
        return dgwsVersion;
    }

    /**
     * Get the ID of this IDCard
     * 
     * @return The value of the SAML attribute named "sosi:IDCardID"
     */
    public String getIdCardId() {
        return idCardId;
    }

    /**
     * Get the care provider id of this IDCard
     * 
     * @return The value of the SAML attribute named "medcom:CareProviderID"
     */
    public String getCareProviderId() {
        return careProviderId;
    }

    /**
     * Get the NameFormat of the care provider id attribute of this IDCard
     * 
     * @return The NameFormat of the SAML attribute named "medcom:CareProviderID" - typically "medcom:cvrnumber"
     */
    public String getCareProviderIdNameFormat() {
        return careProviderIdNameFormat;
    }

    /**
     * Get the care provider name of this IDCard
     * 
     * @return The value of the SAML attribute named "medcom:CareProviderName"
     */
    public String getCareProviderName() {
        return careProviderName;
    }

    protected void extractSamlAttributes(Element signedIdCard) {
        XPathContext xpathContext = new XPathContext(signedIdCard.getOwnerDocument());

        idCardType = getSamlAttribute(xpathContext, signedIdCard, SOSI_IDCARD_TYPE);
        authLevel = Integer.parseInt(getSamlAttribute(xpathContext, signedIdCard, SOSI_AUTH_LEVEL));
        dgwsVersion = getSamlAttribute(xpathContext, signedIdCard, SOSI_IDCARD_VERSION);
        idCardId = getSamlAttribute(xpathContext, signedIdCard, SOSI_IDCARD_ID);
        itSystemName = getSamlAttribute(xpathContext, signedIdCard, MEDCOM_IT_SYSTEM_NAME);
        careProviderId = getSamlAttribute(xpathContext, signedIdCard, MEDCOM_CARE_PROVIDER_ID);
        careProviderIdNameFormat = getSamlAttributeNameFormat(xpathContext, signedIdCard, MEDCOM_CARE_PROVIDER_ID);
        careProviderName = getSamlAttribute(xpathContext, signedIdCard, MEDCOM_CARE_PROVIDER_NAME);

        extractSamlAttributes(signedIdCard, xpathContext);
    }

    protected abstract void extractSamlAttributes(Element signedIdCard, XPathContext xpathContext);

    protected String getSamlAttribute(XPathContext xpathContext, Element rootElement, String attributeName) {
        String path = "//" + NsPrefixes.saml.name() + ":Assertion/" +
                NsPrefixes.saml.name() + ":AttributeStatement/" + NsPrefixes.saml.name() + ":Attribute[@Name='" + attributeName + "']/" + NsPrefixes.saml.name()
                + ":AttributeValue";
        try {
            Element element = xpathContext.findElement(rootElement, path);
            return element != null ? element.getTextContent() : null;
        } catch (XPathExpressionException e) {
            throw new IllegalArgumentException("Error searching for saml attribute '" + attributeName + "'", e);
        }
    }

    protected String getSamlAttributeNameFormat(XPathContext xpathContext, Element rootElement, String attributeName) {
        String path = "//" + NsPrefixes.saml.name() + ":Assertion/" +
                NsPrefixes.saml.name() + ":AttributeStatement/" + NsPrefixes.saml.name() + ":Attribute[@Name='" + attributeName + "']";
        try {
            Element element = xpathContext.findElement(rootElement, path);
            return element != null ? element.getAttribute("NameFormat") : null;
        } catch (XPathExpressionException e) {
            throw new IllegalArgumentException("Error searching for saml attribute '" + attributeName + "'", e);
        }
    }

    protected abstract void extractKeystoreOwnerInfo(X509Certificate cert);

    /**
     * Sign this IDCard, i.e., send at request to SOSI STS requesting a signed DGWS 1.0.1 IDCard.
     * 
     * @throws Exception
     */
    public void sign() throws Exception {
        sign(false);
    }

    /**
     * <p>
     * Sign this IDCard, i.e., send at request to SOSI STS requesting a signed IDCard using the deprecated
     * SecurityTokenService rather than the recommended NewSecurityTokenService
     * </p>
     * <p>
     * Included for test usage - NOT RECOMMENDED FOR PRODUCTION!
     * </p>
     * 
     * @throws Exception
     */
    public void signUsingLegacySTSService() throws Exception {
        sign(true);
    }

    protected void sign(boolean useLegacySTSService) throws Exception {

        Instant now = Instant.now();

        System.setProperty("com.sun.org.apache.xml.internal.security.ignoreLineBreaks", "true");

        DocumentBuilder docBuilder = XmlUtil.getDocBuilder();

        Document doc = docBuilder.newDocument();

        extractKeystoreOwnerInfo(certificate);

        Element idcard = createUnsignedIdCard(doc, certificate, now);

        Element requestBody = createSignIdCardRequest(doc, idcard, now);

        doc.appendChild(requestBody);

        SignatureUtil.sign(idcard, null, new String[] { "#IDCard" }, "OCESSignature", certificate, privateKey, true);

        String endpoint = useLegacySTSService ? LEGACY_SIGN_IDCARD_ENDPOINT : DEFAULT_SIGN_IDCARD_ENDPOINT;

        Element response = WSHelper.post(docBuilder, requestBody,
                env.getStsBaseUrl() + endpoint, "Issue");

        XPathFactory xpathFactory = XPathFactory.newInstance();
        XPath xpath = xpathFactory.newXPath();
        signedIdCard = (Element) xpath.evaluate("//*[@id='IDCard']", response.getOwnerDocument(), XPathConstants.NODE);
        signedIdCard.setIdAttribute("id", true);

        extractSamlAttributes(signedIdCard);
    }

    /**
     * Exchange this IDCard to an OIOSAML assertion that can be used for logging in via SBO (Safe Browser Start) on a web application
     * 
     * @param audience
     *            The requested audience for the IDWS token, e.g. "https://saml.test1.fmk.netic.dk/fmk/". This equals the SAML EntityID of the target web
     *            application.
     * @return
     * @throws ParserConfigurationException
     * @throws IOException
     * @throws InterruptedException
     * @throws STSInvocationException
     * @throws XPathExpressionException
     * @throws SAXException
     * @throws CertificateException
     * @throws NoSuchAlgorithmException
     * @throws KeyStoreException
     * @throws UnrecoverableKeyException
     * @throws BadPaddingException 
     * @throws IllegalBlockSizeException 
     * @throws InvalidAlgorithmParameterException 
     * @throws NoSuchPaddingException 
     * @throws InvalidKeyException 
     */
    public OIOSAMLToken exchangeToOIOSAMLToken(String audience)
            throws ParserConfigurationException, IOException, InterruptedException, STSInvocationException, XPathExpressionException,
            UnrecoverableKeyException, KeyStoreException, NoSuchAlgorithmException, CertificateException, SAXException, InvalidKeyException, 
            NoSuchPaddingException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
        if (signedIdCard == null) {
            throw new IllegalStateException("IdCard must be signed before it can be exchanged");
        }

        Element request = createIdCardToSAMLTokenRequest(signedIdCard.getOwnerDocument(), signedIdCard, audience);

        Element response = WSHelper.post(request,
                env.getStsBaseUrl() + DEFAULT_IDCARD_TO_TOKEN_ENDPOINT, "Ibo");

        XPathContext xpath = new XPathContext(response.getOwnerDocument());

        Element requestedSecurityToken = xpath.findElement(IDCARD_TO_TOKEN_RESPONSE_XPATH);

        assertion = XmlUtil.getChild(requestedSecurityToken, NsPrefixes.saml, "Assertion");
        if (assertion == null) {
            assertion = XmlUtil.getChild(requestedSecurityToken, NsPrefixes.saml, "EncryptedAssertion");
        }

        CertAndKey spCertAndKey = new CertAndKey(certificate, (PrivateKey) privateKey);
        return new OIOSAMLTokenBuilder().env(env).spCertAndKey(spCertAndKey).assertion(assertion).build();
    }

    /**
     * Get the XML representation of this IDCard as a String.
     * 
     * @return The XML
     * @throws UnsupportedEncodingException
     */
    public String getXml() throws UnsupportedEncodingException {
        return XmlUtil.node2String(signedIdCard, false, false);
    }

    /**
     * Get the XML representation of this IDCard as a String.
     * 
     * @param pretty
     *            Format the returned XML
     * @param includeXMLHeader
     *            Include XML header in the returned XML
     * @return The XML
     * @throws UnsupportedEncodingException
     */
    public String getXml(boolean pretty, boolean includeXMLHeader) throws UnsupportedEncodingException {
        return XmlUtil.node2String(signedIdCard, pretty, includeXMLHeader);
    }

    private Element createSignIdCardRequest(Document doc, Element idcard, Instant now)
            throws ParserConfigurationException {

        Element envelope = doc.createElementNS(NsPrefixes.soap.namespaceUri, "Envelope");

        Element soapHeader = appendChild(envelope, NsPrefixes.soap, "Header");
        Element security = appendChild(soapHeader, NsPrefixes.wsse, "Security");
        Element timestamp = appendChild(security, NsPrefixes.wsu, "Timestamp");
        appendChild(timestamp, NsPrefixes.wsu, "Created", ISO_WITHOUT_MILLIS_FORMATTER.format(Instant.now()));

        Element soapBody = appendChild(envelope, NsPrefixes.soap, "Body");
        Element requestSecurityToken = appendChild(soapBody, NsPrefixes.wst, "RequestSecurityToken");
        requestSecurityToken.setAttribute("Context", "www.sosi.dk");
        appendChild(requestSecurityToken, NsPrefixes.wst, "TokenType", "urn:oasis:names:tc:SAML:2.0:assertion:");
        appendChild(requestSecurityToken, NsPrefixes.wst, "RequestType",
                "http://schemas.xmlsoap.org/ws/2005/02/trust/Issue");
        Element claims = appendChild(requestSecurityToken, NsPrefixes.wst, "Claims");
        claims.appendChild(idcard);

        // Seal includes an Issuer as below, but this WSA namespace predates WSA 1.0!
        // Element issuer = appendChild(requestSecurityToken, NsPrefixes.wst, "Issuer");
        // Element address = appendChild(issuer, NsPrefixes.wsax, "Address");
        // address.setTextContent("SealJava-2.6.35-TheSOSILibrary");

        return envelope;
    }

    private Element createIdCardToSAMLTokenRequest(Document doc, Element idcard, String audience)
            throws ParserConfigurationException {

        Element envelope = doc.createElementNS(NsPrefixes.soap.namespaceUri, "Envelope");

        Element soapHeader = appendChild(envelope, NsPrefixes.soap, "Header");
        appendChild(soapHeader, NsPrefixes.wsa, "Action",
                "http://docs.oasis-open.org/ws-sx/ws-trust/200512/RST/Issue");
        String msgId = "urn:uuid:" + UUID.randomUUID().toString();
        appendChild(soapHeader, NsPrefixes.wsa, "MessageID", msgId);

        Element soapBody = appendChild(envelope, NsPrefixes.soap, "Body");

        Element requestSecurityToken = appendChild(soapBody, NsPrefixes.wst13, "RequestSecurityToken");
        requestSecurityToken.setAttribute("Context", msgId);
        appendChild(requestSecurityToken, NsPrefixes.wst13, "TokenType",
                "http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.1#SAMLV2.0");
        appendChild(requestSecurityToken, NsPrefixes.wst13, "RequestType",
                "http://docs.oasis-open.org/ws-sx/ws-trust/200512/Issue");

        Element actAs = appendChild(requestSecurityToken, NsPrefixes.wst14, "ActAs");
        actAs.appendChild(idcard);

        Element appliesTo = appendChild(requestSecurityToken, NsPrefixes.wsp, "AppliesTo");
        Element endpointRef = appendChild(appliesTo, NsPrefixes.wsa, "EndpointReference");
        appendChild(endpointRef, NsPrefixes.wsa, "Address", audience);

        return envelope;
    }

    private Element createUnsignedIdCard(Document doc, Certificate certificate, Instant now) throws Exception {

        Element assertion = doc.createElementNS(NsPrefixes.saml.namespaceUri, "Assertion");

        assertion.setAttribute("IssueInstant", ISO_WITHOUT_MILLIS_FORMATTER.format(now));
        assertion.setAttribute("Version", "2.0");
        assertion.setAttribute("id", "IDCard");
        assertion.setIdAttribute("id", true);

        appendChild(assertion, NsPrefixes.saml, "Issuer", "Unsealed");
        Element subject = appendChild(assertion, NsPrefixes.saml, "Subject");

        addSubjectAttributes(subject);

        Element subjectConfirmation = appendChild(subject, NsPrefixes.saml, "SubjectConfirmation");
        appendChild(subjectConfirmation, NsPrefixes.saml, "ConfirmationMethod",
                "urn:oasis:names:tc:SAML:2.0:cm:holder-of-key");

        Element keyInfo = appendChild(appendChild(subjectConfirmation, NsPrefixes.saml, "SubjectConfirmationData"),
                NsPrefixes.ds, "KeyInfo");

        appendChild(keyInfo, NsPrefixes.ds, "KeyName", "OCESSignature");
        Element conditions = appendChild(assertion, NsPrefixes.saml, "Conditions");
        Instant validFrom = now.minusSeconds(NOT_BEFORE_ALLOWED_SLACK);
        conditions.setAttribute("NotBefore", ISO_WITHOUT_MILLIS_FORMATTER.format(validFrom));
        conditions.setAttribute("NotOnOrAfter",
                ISO_WITHOUT_MILLIS_FORMATTER.format(validFrom.plus(24, ChronoUnit.HOURS)));

        Element idCardData = appendChild(assertion, NsPrefixes.saml, "AttributeStatement");
        idCardData.setAttribute("id", "IDCardData");

        SamlUtil.addSamlAttribute(idCardData, "sosi:IDCardID", UUID.randomUUID().toString());

        SamlUtil.addSamlAttribute(idCardData, "sosi:IDCardVersion", useLegacyDGWS_1_0 ? "1.0" : "1.0.1");

        SamlUtil.addSamlAttribute(idCardData, "sosi:OCESCertHash", SignatureUtil.getDigestOfCertificate(certificate));

        addTypeSpecificAttributes(idCardData, assertion);

        Element systemLog = appendChild(assertion, NsPrefixes.saml, "AttributeStatement");
        systemLog.setAttribute("id", "SystemLog");
        // systemLog.setIdAttribute("id", true);

        if (systemName != null) {
            SamlUtil.addSamlAttribute(systemLog, "medcom:ITSystemName", systemName);
        }

        SamlUtil.addSamlAttribute(systemLog, "medcom:CareProviderID", cvr, "medcom:cvrnumber");

        SamlUtil.addSamlAttribute(systemLog, "medcom:CareProviderName", organisation);

        return assertion;
    }

    protected abstract void addSubjectAttributes(Element assertion);

    protected abstract void addTypeSpecificAttributes(Element idCardData, Element assertion);

    /**
     * Get the entity id of the issuer of this IDCard
     * 
     * @return The issuer
     */
    public String getIssuer() {
        return getTextChild(signedIdCard, NsPrefixes.saml, "Issuer");
    }

    /**
     * Get any SAML attribute of this IDCard by name.
     * 
     * @param attributeName
     *            The name of the attribute
     * @return
     */
    public String getAttribute(String attributeName) {
        Element rootElement = signedIdCard;
        if (rootElement == null) {
            rootElement = assertion;
        }
        XPathContext xpath = new XPathContext(rootElement.getOwnerDocument());
        return getSamlAttribute(xpath, rootElement, attributeName);
    }

    /**
     * The the subject name of the certificate represented by this IDCard.
     * 
     * @return The subject name
     */
    public String getSubjectName() {
        return getTextChild(getChild(signedIdCard, NsPrefixes.saml, "Subject"), NsPrefixes.saml, "NameID");
    }

    /**
     * Serialise this IDCard to a {@link org.w3c.dom.Document}
     * 
     * @param doc
     * @return The serialised document
     */
    public Element serialize2DOMDocument(Document doc) {
        if (!signedIdCard.getOwnerDocument().equals(doc)) {
            // Import the IDCard DOM element into the new document
            return (Element) doc.importNode(signedIdCard, true);
        }

        return signedIdCard;
    }

    /**
     * Get the NotBefore condition (valid from time) of this IDCard
     * 
     * @return The NotBefore condition as a {@link java.time.ZonedDateTime}
     */
    public ZonedDateTime getNotBefore() {
        Element cond = getChild(signedIdCard, NsPrefixes.saml, "Conditions");
        return parseDate(cond.getAttribute("NotBefore"));
    }

    /**
     * Get the NotOnOrAfter condition (expiration time) of this IDCard
     * 
     * @return The NotOnOrAftter condition as a {@link java.time.ZonedDateTime}
     */
    public ZonedDateTime getNotOnOrAfter() {
        Element cond = getChild(signedIdCard, NsPrefixes.saml, "Conditions");
        return parseDate(cond.getAttribute("NotOnOrAfter"));
    }

    /**
     * Validate this IDCard, i.e. validate than NotBefore/NotOnOrAfter is satisfied and that the signature of the assertion/IDCard is valid.
     * 
     * @throws ValidationException
     */
    public void validate() throws ValidationException {
        validateTimes(null);
        validateSignature();
    }

    /**
     * Get a reference to the {@link org.w3c.dom.Element} representation of this IDCard.
     * 
     * @return A reference to the assertion
     */
    public Element getAssertion() {
        return signedIdCard != null ? signedIdCard : assertion;
    }

    private ZonedDateTime parseDate(String dateTime) {
        if ("1.0.1".equals(dgwsVersion)) {
            return ZonedDateTime.parse(dateTime, ISO_WITHOUT_MILLIS_FORMATTER);
        } else if ("1.0".equals(dgwsVersion)) {
            return LocalDateTime.parse(dateTime).atZone(ZoneId.systemDefault());
        } else {
            throw new IllegalStateException("Unexpected DGWS version \"" + dgwsVersion + "\"");
        }
    }

    private void validateSignature() throws ValidationException {
        try {
            // STS signs SOSI IdCards rsa-sha1 which is considered unsafe by Java 17..
            SignatureUtil.validate(signedIdCard, true);
        } catch (MarshalException | XMLSignatureException e) {
            throw new ValidationException("Error validating signature", e);
        }
    }

    private void validateTimes(ZonedDateTime now) throws ValidationException {
        if (now == null) {
            now = ZonedDateTime.now();
        }

        ZonedDateTime notBefore = getNotBefore();
        if (now.isBefore(notBefore)) {
            throw new ValidationException("NotBefore condition not met, NotBefore=" + notBefore + ", now=" + now);
        }

        ZonedDateTime notOnOrAfter = getNotOnOrAfter();
        if (now.isEqual(notOnOrAfter) || now.isAfter(notOnOrAfter)) {
            throw new ValidationException("NotOnOrAfter condition not met, NotOnOrAfter=" + notOnOrAfter + ", now=" + now);
        }
    }
}