package com.trifork.unsealed;

import static com.trifork.unsealed.XmlUtil.appendChild;
import static java.util.logging.Level.FINE;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.time.temporal.ChronoUnit;
import java.util.UUID;
import java.util.logging.Logger;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathFactory;

import org.w3c.dom.Document;
import org.w3c.dom.Element;

public abstract class IdCard {
    private static final Logger logger = Logger.getLogger(IdCard.class.getName());

    public static final String DEFAULT_SIGN_IDCARD_ENDPOINT = "/sts/services/NewSecurityTokenService";
    public static final String DEFAULT_IDCARD_TO_TOKEN_ENDPOINT = "/sts/services/Sosi2OIOSaml";

    static final DateTimeFormatter formatter = DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ss'Z'")
            .withZone(ZoneId.of("UTC"));

    private NSPEnv env;
    protected String cvr;
    protected String organisation;
    private X509Certificate certificate;
    private Key privateKey;
    private String systemName;

    private Element signedIdCard;


    protected IdCard(NSPEnv env, X509Certificate certificate, Key privateKey, String systemName) {
        this.env = env;
        this.certificate = certificate;
        this.privateKey = privateKey;
        this.systemName = systemName;
    }

    protected abstract void extractKeystoreOwnerInfo(X509Certificate cert);

    public void sign() throws Exception {

        Instant now = Instant.now();

        System.setProperty("com.sun.org.apache.xml.internal.security.ignoreLineBreaks", "true");

        DocumentBuilder docBuilder = getDocBuilder();

        Document doc = docBuilder.newDocument();

        extractKeystoreOwnerInfo(certificate);

        Element idcard = createUnsignedIdCard(doc, certificate, now);

        Element requestBody = createSignIdCardRequest(doc, idcard, now);

        doc.appendChild(requestBody);

        // Without this, canonicalisation/digest calculation is incorrect
        doc.normalizeDocument();

        SignatureUtil.sign(idcard, null, new String[] { "#IDCard" }, "OCESSignature", certificate, privateKey, true);

        logger.log(FINE, "Request body: " + XmlUtil.node2String(requestBody, true, false));

        // writeElementToFile(doc.getElementById("IDCard"), "idcard.xml");

        String response = WSHelper.post(XmlUtil.node2String(requestBody, false, false),
                env.getStsBaseUrl() + DEFAULT_SIGN_IDCARD_ENDPOINT, "Issue");

        logger.log(FINE, "Response: " + response);

        Document newDoc = docBuilder.parse(new ByteArrayInputStream(response.getBytes((StandardCharsets.UTF_8))));

        XPathFactory xpathFactory = XPathFactory.newInstance();
        XPath xpath = xpathFactory.newXPath();
        signedIdCard = (Element) xpath.evaluate("//*[@id='IDCard']", newDoc, XPathConstants.NODE);
        signedIdCard.setIdAttribute("id", true);

        // signedIdCard = (Element) newDoc.getElementsByTagNameNS(NsPrefixes.saml,
        // "Assertion").item(0);

    }

    public OIOSAMLToken exchangeToOIOSAMLToken(String audience)
            throws ParserConfigurationException, IOException, InterruptedException {
        if (signedIdCard == null) {
            throw new IllegalStateException("IdCard must be signed before it can be exchanged");
        }

        Element request = createIdCardToSAMLTokenRequest(signedIdCard.getOwnerDocument(), signedIdCard, audience);

        logger.log(FINE, "Request body: " + XmlUtil.node2String(request, true, false));

        String response = WSHelper.post(XmlUtil.node2String(request, false, false),
                env.getStsBaseUrl() + DEFAULT_IDCARD_TO_TOKEN_ENDPOINT, "Ibo");

        logger.log(FINE, "Response: " + response);

        return null;
    }

    static DocumentBuilder getDocBuilder() throws ParserConfigurationException {
        // Neither DocumentBuilderFactory nor DocumentBuilder are guarenteed to be
        // thread safe
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.setNamespaceAware(true);
        return dbf.newDocumentBuilder();
    }

    private Element createSignIdCardRequest(Document doc, Element idcard, Instant now)
            throws ParserConfigurationException {

        Element envelope = doc.createElementNS(NsPrefixes.soap.namespaceUri, "Envelope");

        Element soapHeader = appendChild(envelope, NsPrefixes.soap, "Header");
        Element security = appendChild(soapHeader, NsPrefixes.wsse, "Security");
        Element timestamp = appendChild(security, NsPrefixes.wsu, "Timestamp");
        appendChild(timestamp, NsPrefixes.wsu, "Created", formatter.format(Instant.now()));

        Element soapBody = appendChild(envelope, NsPrefixes.soap, "Body");
        Element requestSecurityToken = appendChild(soapBody, NsPrefixes.wst, "RequestSecurityToken");
        requestSecurityToken.setAttribute("Context", "www.sosi.dk");
        appendChild(requestSecurityToken, NsPrefixes.wst, "TokenType", "urn:oasis:names:tc:SAML:2.0:assertion:");
        appendChild(requestSecurityToken, NsPrefixes.wst, "RequestType", "http://schemas.xmlsoap.org/ws/2005/02/trust/Issue");
        Element claims = appendChild(requestSecurityToken, NsPrefixes.wst, "Claims");
        claims.appendChild(idcard);

        return envelope;
    }

    private Element createIdCardToSAMLTokenRequest(Document doc, Element idcard, String audience)
            throws ParserConfigurationException {

        Element envelope = doc.createElementNS(NsPrefixes.soap.namespaceUri, "Envelope");

        Element soapHeader = appendChild(envelope, NsPrefixes.soap, "Header");
        appendChild(soapHeader, NsPrefixes.wsa10, "Action", "http://docs.oasis-open.org/ws-sx/ws-trust/200512/RST/Issue");
        String msgId = "urn:uuid:" + UUID.randomUUID().toString();
        appendChild(soapHeader, NsPrefixes.wsa10, "MessageID", msgId);

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
        Element endpointRef = appendChild(appliesTo, NsPrefixes.wsa10, "EndpointReference");
        appendChild(endpointRef, NsPrefixes.wsa10, "Address", audience);

        return envelope;
    }

    private Element createUnsignedIdCard(Document doc, Certificate certificate, Instant now) throws Exception {

        Element assertion = doc.createElementNS(NsPrefixes.saml.namespaceUri, "Assertion");

        assertion.setAttribute("IssueInstant", formatter.format(now));
        assertion.setAttribute("Version", "2.0");
        assertion.setAttribute("id", "IDCard");
        assertion.setIdAttribute("id", true);

        appendChild(assertion, NsPrefixes.saml, "Issuer", "The SOSI library");
        Element subject = appendChild(assertion, NsPrefixes.saml, "Subject");

        addSubjectAttributes(subject);

        Element subjectConfirmation = appendChild(subject, NsPrefixes.saml, "SubjectConfirmation");
        appendChild(subjectConfirmation, NsPrefixes.saml, "ConfirmationMethod", "urn:oasis:names:tc:SAML:2.0:cm:holder-of-key");

        Element keyInfo = appendChild(appendChild(subjectConfirmation, NsPrefixes.saml, "SubjectConfirmationData"), NsPrefixes.ds,
                "KeyInfo");

        appendChild(keyInfo, NsPrefixes.ds, "KeyName", "OCESSignature");
        Element conditions = appendChild(assertion, NsPrefixes.saml, "Conditions");
        Instant validFrom = now.minusMillis(1000);
        conditions.setAttribute("NotBefore", formatter.format(validFrom));
        conditions.setAttribute("NotOnOrAfter", formatter.format(validFrom.plus(24, ChronoUnit.HOURS)));

        Element idCardData = appendChild(assertion, NsPrefixes.saml, "AttributeStatement");
        idCardData.setAttribute("id", "IDCardData");

        addSamlAttribute(idCardData, "sosi:IDCardID", UUID.randomUUID().toString());

        addSamlAttribute(idCardData, "sosi:IDCardVersion", "1.0.1");

        addSamlAttribute(idCardData, "sosi:OCESCertHash", SignatureUtil.getDigestOfCertificate(certificate));

        addTypeSpecificAttributes(idCardData, assertion);

        Element systemLog = appendChild(assertion, NsPrefixes.saml, "AttributeStatement");
        systemLog.setAttribute("id", "SystemLog");
        // systemLog.setIdAttribute("id", true);

        if (systemName != null) {
            addSamlAttribute(systemLog, "medcom:ITSystemName", systemName);
        }

        addSamlAttribute(systemLog, "medcom:CareProviderID", cvr, "medcom:cvrnumber");

        addSamlAttribute(systemLog, "medcom:CareProviderName", organisation);

        return assertion;
    }

    protected abstract void addSubjectAttributes(Element assertion);

    protected abstract void addTypeSpecificAttributes(Element idCardData, Element assertion);

    protected void addSamlAttribute(Element parent, String name, String value) {
        addSamlAttribute(parent, name, value, null);
    }

    private void addSamlAttribute(Element parent, String name, String value, String nameFormat) {
        Element attr = appendChild(parent, NsPrefixes.saml, "Attribute");
        attr.setAttribute("Name", name);
        if (nameFormat != null) {
            attr.setAttribute("NameFormat", nameFormat);
        }
        appendChild(attr, NsPrefixes.saml, "AttributeValue", value);
    }

}