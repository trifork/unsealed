package com.trifork.unsealed;

import static com.trifork.unsealed.XmlUtil.ISO_WITHOUT_MILLIS_FORMATTER;
import static com.trifork.unsealed.XmlUtil.appendChild;
import static com.trifork.unsealed.XmlUtil.getChild;
import static com.trifork.unsealed.XmlUtil.getTextChild;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.Key;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.temporal.ChronoUnit;
import java.util.UUID;

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

public abstract class IdCard {
    public static final String DEFAULT_SIGN_IDCARD_ENDPOINT = "/sts/services/NewSecurityTokenService";
    public static final String DEFAULT_IDCARD_TO_TOKEN_ENDPOINT = "/sts/services/Sosi2OIOSaml";

    private static final String IDCARD_TO_TOKEN_RESPONSE_XPATH = "/" + NsPrefixes.soap.name() + ":Envelope/"
    + NsPrefixes.soap.name() + ":Body/" + NsPrefixes.wst13.name() + ":RequestSecurityTokenResponseCollection/"
    + NsPrefixes.wst13.name() + ":RequestSecurityTokenResponse/" + NsPrefixes.wst13.name() + ":RequestedSecurityToken";

    private NSPEnv env;
    protected String cvr;
    protected String organisation;
    private X509Certificate certificate;
    private Key privateKey;
    private String systemName;

    protected Element signedIdCard;

    private Element assertion;

    private Element encryptedAssertion;

    protected IdCard(NSPEnv env, X509Certificate certificate, Key privateKey, String systemName) {
        this.env = env;
        this.certificate = certificate;
        this.privateKey = privateKey;
        this.systemName = systemName;
    }

    IdCard(NSPEnv env, Element signedIdCard) {
        this.env = env;
        this.signedIdCard = signedIdCard;
    }

    protected abstract void extractKeystoreOwnerInfo(X509Certificate cert);

    public void sign() throws Exception {

        Instant now = Instant.now();

        System.setProperty("com.sun.org.apache.xml.internal.security.ignoreLineBreaks", "true");

        DocumentBuilder docBuilder = XmlUtil.getDocBuilder();

        Document doc = docBuilder.newDocument();

        extractKeystoreOwnerInfo(certificate);

        Element idcard = createUnsignedIdCard(doc, certificate, now);

        Element requestBody = createSignIdCardRequest(doc, idcard, now);

        doc.appendChild(requestBody);

        SignatureUtil.sign(idcard, null, new String[] { "#IDCard" }, "OCESSignature", certificate, privateKey, true);

        Element response = WSHelper.post(docBuilder, requestBody,
                env.getStsBaseUrl() + DEFAULT_SIGN_IDCARD_ENDPOINT, "Issue");

        XPathFactory xpathFactory = XPathFactory.newInstance();
        XPath xpath = xpathFactory.newXPath();
        signedIdCard = (Element) xpath.evaluate("//*[@id='IDCard']", response.getOwnerDocument(), XPathConstants.NODE);
        signedIdCard.setIdAttribute("id", true);
    }

    public OIOSAMLToken exchangeToOIOSAMLToken(String audience) throws ParserConfigurationException, IOException,
            InterruptedException, STSInvocationException, XPathExpressionException {
        if (signedIdCard == null) {
            throw new IllegalStateException("IdCard must be signed before it can be exchanged");
        }

        Element request = createIdCardToSAMLTokenRequest(signedIdCard.getOwnerDocument(), signedIdCard, audience);

        Element response = WSHelper.post(request,
                env.getStsBaseUrl() + DEFAULT_IDCARD_TO_TOKEN_ENDPOINT, "Ibo");

        XPathContext xpath = new XPathContext(response.getOwnerDocument());

        Element requestedSecurityToken = xpath.findElement(IDCARD_TO_TOKEN_RESPONSE_XPATH);

        assertion = XmlUtil.getChild(requestedSecurityToken, NsPrefixes.saml, "Assertion");
        if (assertion != null) {
            return new OIOSAMLToken(env, null, null, assertion, false);
        }
        
        encryptedAssertion = XmlUtil.getChild(requestedSecurityToken, NsPrefixes.saml, "EncryptedAssertion");
        return new OIOSAMLToken(env, null, null, encryptedAssertion, true);
    }

    public String getXml() throws UnsupportedEncodingException {
        return XmlUtil.node2String(signedIdCard, false, false);
    }

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

        appendChild(assertion, NsPrefixes.saml, "Issuer", "The SOSI library");
        Element subject = appendChild(assertion, NsPrefixes.saml, "Subject");

        addSubjectAttributes(subject);

        Element subjectConfirmation = appendChild(subject, NsPrefixes.saml, "SubjectConfirmation");
        appendChild(subjectConfirmation, NsPrefixes.saml, "ConfirmationMethod",
                "urn:oasis:names:tc:SAML:2.0:cm:holder-of-key");

        Element keyInfo = appendChild(appendChild(subjectConfirmation, NsPrefixes.saml, "SubjectConfirmationData"),
                NsPrefixes.ds, "KeyInfo");

        appendChild(keyInfo, NsPrefixes.ds, "KeyName", "OCESSignature");
        Element conditions = appendChild(assertion, NsPrefixes.saml, "Conditions");
        Instant validFrom = now.minusMillis(1000);
        conditions.setAttribute("NotBefore", ISO_WITHOUT_MILLIS_FORMATTER.format(validFrom));
        conditions.setAttribute("NotOnOrAfter",
                ISO_WITHOUT_MILLIS_FORMATTER.format(validFrom.plus(24, ChronoUnit.HOURS)));

        Element idCardData = appendChild(assertion, NsPrefixes.saml, "AttributeStatement");
        idCardData.setAttribute("id", "IDCardData");

        SamlUtil.addSamlAttribute(idCardData, "sosi:IDCardID", UUID.randomUUID().toString());

        SamlUtil.addSamlAttribute(idCardData, "sosi:IDCardVersion", "1.0.1");

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

    public String getIssuer() {
        return getTextChild(signedIdCard, NsPrefixes.saml, "Issuer");
    }

    public String getAttribute(String attributeName) {
        Element assertionElm = signedIdCard;
        if (assertionElm == null) {
            assertionElm = assertion;
        }
        XPathContext xpath = new XPathContext(assertionElm.getOwnerDocument());
        String path = "//" + NsPrefixes.saml.name() + ":Assertion/" + 
            NsPrefixes.saml.name() + ":AttributeStatement/" + NsPrefixes.saml.name() + ":Attribute[@Name='" + attributeName + "']/" + NsPrefixes.saml.name() + ":AttributeValue";
            try {
            Element element = xpath.findElement(assertionElm, path);
            return element != null ? element.getTextContent() : null;
        } catch (XPathExpressionException e) {
            throw new IllegalArgumentException("Error searching for saml attribute '" + attributeName + "'", e);
        }
    }

    public String getSubjectName() {
        return getTextChild(getChild(signedIdCard, NsPrefixes.saml, "Subject"), NsPrefixes.saml, "NameID");
    }

    public Element serialize2DOMDocument(Document doc) {
        if (!signedIdCard.getOwnerDocument().equals(doc)) {
            // Import the IDCard DOM element into the new document
            return (Element) doc.importNode(signedIdCard, true);
        }

        return signedIdCard;
    }

    public LocalDateTime getNotBefore() {
        Element cond = getChild(signedIdCard, NsPrefixes.saml, "Conditions");
        return LocalDateTime.parse(cond.getAttribute("NotBefore"), ISO_WITHOUT_MILLIS_FORMATTER);
    }

    public LocalDateTime getNotOnOrAfter() {
        Element cond = getChild(signedIdCard, NsPrefixes.saml, "Conditions");
        return LocalDateTime.parse(cond.getAttribute("NotOnOrAfter"), ISO_WITHOUT_MILLIS_FORMATTER);
    }

    public void validate() throws ValidationException {
        validateTimes(null);
        validateSignature();
    }

    public Element getAssertion() {
        return signedIdCard != null ? signedIdCard : assertion;
    }

    private void validateSignature() throws ValidationException {
        try {
            SignatureUtil.validate(signedIdCard);
        } catch (MarshalException | XMLSignatureException e) {
            throw new ValidationException("Error validating signature", e);
        }
    }

    private void validateTimes(LocalDateTime now) throws ValidationException {
        if (now == null) {
            now = LocalDateTime.now();
        }
        
        LocalDateTime notBefore = getNotBefore();
        if (now.isBefore(notBefore)) {
            throw new ValidationException("NotBefore condition not met, NotBefore=" + notBefore + ", now=" + now);
        }

        LocalDateTime notOnOrAfter = getNotOnOrAfter();
        if (now.isEqual(notOnOrAfter) || now.isAfter(notOnOrAfter)) {
            throw new ValidationException("NotOnOrAfter condition not met, NotOnOrAfter=" + notOnOrAfter + ", now=" + now);
        }
    }
}