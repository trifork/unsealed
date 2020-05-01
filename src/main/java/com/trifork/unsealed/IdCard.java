package com.trifork.unsealed;

import static com.trifork.unsealed.XmlUtil.appendChild;
import static java.util.logging.Level.FINE;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.time.temporal.ChronoUnit;
import java.util.UUID;
import java.util.logging.Logger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathFactory;

import org.w3c.dom.Document;
import org.w3c.dom.Element;

public class IdCard {
    private static final Logger logger = Logger.getLogger(IdCard.class.getName());

    public static final String DEFAULT_SIGN_IDCARD_ENDPOINT = "/sts/services/NewSecurityTokenService";
    public static final String DEFAULT_IDCARD_TO_TOKEN_ENDPOINT = "/sts/services/Sosi2OIOSaml";
    private static final String KEYSTORE_PASSWORD = "Test1234";
    private static final String DS_NS = "http://www.w3.org/2000/09/xmldsig#";
    private static final String SOAPENV_NS = "http://schemas.xmlsoap.org/soap/envelope/";
    private static final String SAML_NS = "urn:oasis:names:tc:SAML:2.0:assertion";
    private static final String WSA2_NS = "http://www.w3.org/2005/08/addressing";
    private static final String WSSE_NS = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd";
    private static final String WST_NS = "http://schemas.xmlsoap.org/ws/2005/02/trust";
    public static final String WST_1_3_SCHEMA = "http://docs.oasis-open.org/ws-sx/ws-trust/200512";
    public static final String WST_1_4_SCHEMA = "http://docs.oasis-open.org/ws-sx/ws-trust/200802";
    private static final String WSU_NS = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd";
    private static final String WSP_NS = "http://schemas.xmlsoap.org/ws/2004/09/policy";
    private static final Pattern mocesSubjectRegex = Pattern
            .compile("CN=([^\\+ ]+) ([^\\+]+) \\+ SERIALNUMBER=CVR:(\\d+)-RID:(\\d+), O=([^,]+), C=(\\w\\w)");

    private static final DateTimeFormatter formatter = DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ss'Z'")
            .withZone(ZoneId.of("UTC"));

    private NSPEnv env;
    private String cpr;
    private KeyStore keystore;
    private String firstName;
    private String lastName;
    private String cvr;
    private String organisation;
    private String email;
    private String role;
    private String occupation;
    private String authorizationCode;
    private String systemName;

    private Element signedIdCard;

    protected IdCard(NSPEnv env, String cpr, KeyStore keystore, String email, String role, String occupation,
            String authorizationCode, String systemName) {
        this.env = env;
        this.cpr = cpr;
        this.keystore = keystore;
        this.email = email;
        this.role = role;
        this.occupation = occupation;
        this.authorizationCode = authorizationCode;
        this.systemName = systemName;
    }

    private void extractKeystoreOwnerInfo(X509Certificate cert) {
        String subject = cert.getSubjectDN().getName();
        Matcher matcher = mocesSubjectRegex.matcher(subject);
        if (matcher.matches()) {
            firstName = matcher.group(1);
            lastName = matcher.group(2);
            cvr = matcher.group(3);
            // rid = matcher.group(4);
            organisation = matcher.group(5);

            int idx = organisation.indexOf(" // CVR:");
            if (idx != -1) {
                organisation = organisation.substring(0, idx);
            }
        }

    }

    public void sign() throws Exception {

        Instant now = Instant.now();

        System.setProperty("com.sun.org.apache.xml.internal.security.ignoreLineBreaks", "true");

        DocumentBuilder docBuilder = getDocBuilder();

        Document doc = docBuilder.newDocument();

        Certificate certificate = keystore.getCertificate(keystore.aliases().nextElement());

        extractKeystoreOwnerInfo((X509Certificate) certificate);

        Key privateKey = keystore.getKey(keystore.aliases().nextElement(), KEYSTORE_PASSWORD.toCharArray());

        Element idcard = createUnsignedIdCard(doc, certificate, now);

        OutputStream os = new ByteArrayOutputStream();

        Element requestBody = createSignIdCardRequest(doc, idcard, now);

        doc.appendChild(requestBody);

        // Without this, canonicalisation/digest calculation is incorrect
        doc.normalizeDocument();

        SignatureUtil.sign(idcard, "#IDCard", "OCESSignature", certificate, privateKey, os);

        logger.log(FINE, "Request body: " + XmlUtil.node2String(requestBody, true, false));

        writeElementToFile(doc.getElementById("IDCard"), "idcard.xml");

        String response = WSHelper.post(XmlUtil.node2String(requestBody, false, false),
                env.getStsBaseUrl() + DEFAULT_SIGN_IDCARD_ENDPOINT, "Issue");

        logger.log(FINE, "Response: " + response);

        Document newDoc = docBuilder.parse(new ByteArrayInputStream(response.getBytes((StandardCharsets.UTF_8))));

        XPathFactory xpathFactory = XPathFactory.newInstance();
        XPath xpath = xpathFactory.newXPath();
        signedIdCard = (Element) xpath.evaluate("//*[@id='IDCard']", newDoc, XPathConstants.NODE);
        signedIdCard.setIdAttribute("id", true);

        // signedIdCard = (Element) newDoc.getElementsByTagNameNS(SAML_NS,
        // "Assertion").item(0);

    }

    public SAMLToken exchangeToSAMLToken(String audience)
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

    private DocumentBuilder getDocBuilder() throws ParserConfigurationException {
        // Neither DocumentBuilderFactory nor DocumentBuilder are guarenteed to be
        // thread safe
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.setNamespaceAware(true);
        return dbf.newDocumentBuilder();
    }

    private Element createSignIdCardRequest(Document doc, Element idcard, Instant now)
            throws ParserConfigurationException {

        Element envelope = doc.createElementNS(SOAPENV_NS, "Envelope");

        Element soapHeader = appendChild(envelope, SOAPENV_NS, "Header");
        Element security = appendChild(soapHeader, WSSE_NS, "Security");
        Element timestamp = appendChild(security, WSU_NS, "Timestamp");
        appendChild(timestamp, WSU_NS, "Created", formatter.format(Instant.now()));

        Element soapBody = appendChild(envelope, SOAPENV_NS, "Body");
        Element requestSecurityToken = appendChild(soapBody, WST_NS, "RequestSecurityToken");
        requestSecurityToken.setAttribute("Context", "www.sosi.dk");
        appendChild(requestSecurityToken, WST_NS, "TokenType", "urn:oasis:names:tc:SAML:2.0:assertion:");
        appendChild(requestSecurityToken, WST_NS, "RequestType", "http://schemas.xmlsoap.org/ws/2005/02/trust/Issue");
        Element claims = appendChild(requestSecurityToken, WST_NS, "Claims");
        claims.appendChild(idcard);

        return envelope;
    }

    private Element createIdCardToSAMLTokenRequest(Document doc, Element idcard, String audience)
            throws ParserConfigurationException {

        Element envelope = doc.createElementNS(SOAPENV_NS, "Envelope");

        Element soapHeader = appendChild(envelope, SOAPENV_NS, "Header");
        appendChild(soapHeader, WSA2_NS, "Action", "http://docs.oasis-open.org/ws-sx/ws-trust/200512/RST/Issue");
        String msgId = "urn:uuid:" + UUID.randomUUID().toString();
        appendChild(soapHeader, WSA2_NS, "MessageID", msgId);

        Element soapBody = appendChild(envelope, SOAPENV_NS, "Body");

        Element requestSecurityToken = appendChild(soapBody, WST_1_3_SCHEMA, "RequestSecurityToken");
        requestSecurityToken.setAttribute("Context", msgId);
        appendChild(requestSecurityToken, WST_1_3_SCHEMA, "TokenType",
                "http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.1#SAMLV2.0");
        appendChild(requestSecurityToken, WST_1_3_SCHEMA, "RequestType",
                "http://docs.oasis-open.org/ws-sx/ws-trust/200512/Issue");

        Element actAs = appendChild(requestSecurityToken, WST_1_4_SCHEMA, "ActAs");
        actAs.appendChild(idcard);

        Element appliesTo = appendChild(requestSecurityToken, WSP_NS, "AppliesTo");
        Element endpointRef = appendChild(appliesTo, WSA2_NS, "EndpointReference");
        appendChild(endpointRef, WSA2_NS, "Address", audience);

        return envelope;
    }

    private Element createUnsignedIdCard(Document doc, Certificate certificate, Instant now) throws Exception {

        Element assertion = doc.createElementNS(SAML_NS, "Assertion");

        assertion.setAttribute("IssueInstant", formatter.format(now));
        assertion.setAttribute("Version", "2.0");
        assertion.setAttribute("id", "IDCard");
        assertion.setIdAttribute("id", true);

        appendChild(assertion, SAML_NS, "Issuer", firstName + " " + lastName);
        Element subject = appendChild(assertion, SAML_NS, "Subject");
        Element nameId = appendChild(subject, SAML_NS, "NameID", cpr);
        nameId.setAttribute("Format", "medcom:cprnumber");

        Element subjectConfirmation = appendChild(subject, SAML_NS, "SubjectConfirmation");
        appendChild(subjectConfirmation, SAML_NS, "ConfirmationMethod", "urn:oasis:names:tc:SAML:2.0:cm:holder-of-key");

        Element keyInfo = appendChild(appendChild(subjectConfirmation, SAML_NS, "SubjectConfirmationData"), DS_NS,
                "KeyInfo");

        appendChild(keyInfo, DS_NS, "KeyName", "OCESSignature");
        Element conditions = appendChild(assertion, SAML_NS, "Conditions");
        Instant validFrom = now.minusMillis(1000);
        conditions.setAttribute("NotBefore", formatter.format(validFrom));
        conditions.setAttribute("NotOnOrAfter", formatter.format(validFrom.plus(24, ChronoUnit.HOURS)));

        Element idCardData = appendChild(assertion, SAML_NS, "AttributeStatement");
        idCardData.setAttribute("id", "IDCardData");

        addSamlAttribute(idCardData, "sosi:IDCardID", UUID.randomUUID().toString());

        addSamlAttribute(idCardData, "sosi:IDCardVersion", "1.0.1");

        addSamlAttribute(idCardData, "sosi:IDCardType", "user");

        addSamlAttribute(idCardData, "sosi:AuthenticationLevel", "4");

        addSamlAttribute(idCardData, "sosi:OCESCertHash", SignatureUtil.getDigestOfCertificate(certificate));

        Element userLog = appendChild(assertion, SAML_NS, "AttributeStatement");
        userLog.setAttribute("id", "UserLog");
        // userLog.setIdAttribute("id", true);

        addSamlAttribute(userLog, "medcom:UserCivilRegistrationNumber", cpr);

        addSamlAttribute(userLog, "medcom:UserGivenName", firstName);

        addSamlAttribute(userLog, "medcom:UserSurName", lastName);

        if (email != null) {
            addSamlAttribute(userLog, "medcom:UserEmailAddress", email);
        }

        if (role != null) {
            addSamlAttribute(userLog, "medcom:UserRole", role);
        }

        if (occupation != null) {
            addSamlAttribute(userLog, "medcom:UserOccupation", occupation);
        }

        if (authorizationCode != null) {
            addSamlAttribute(userLog, "medcom:AuthorizationCode", authorizationCode);
        }

        Element systemLog = appendChild(assertion, SAML_NS, "AttributeStatement");
        systemLog.setAttribute("id", "SystemLog");
        // systemLog.setIdAttribute("id", true);

        if (systemName != null) {
            addSamlAttribute(systemLog, "medcom:ITSystemName", systemName);
        }

        addSamlAttribute(systemLog, "medcom:CareProviderID", cvr, "medcom:cvrnumber");

        addSamlAttribute(systemLog, "medcom:CareProviderName", organisation);

        return assertion;
    }

    private void addSamlAttribute(Element parent, String name, String value) {
        addSamlAttribute(parent, name, value, null);
    }

    private void addSamlAttribute(Element parent, String name, String value, String nameFormat) {
        Element attr = appendChild(parent, SAML_NS, "Attribute");
        attr.setAttribute("Name", name);
        if (nameFormat != null) {
            attr.setAttribute("NameFormat", nameFormat);
        }
        appendChild(attr, SAML_NS, "AttributeValue", value);
    }

    private void writeElementToFile(Element element, String fileName) throws Exception {
        TransformerFactory transformerFactory = TransformerFactory.newInstance();
        Transformer transformer = transformerFactory.newTransformer();
        DOMSource source = new DOMSource(element);
        FileWriter writer = new FileWriter(new File(fileName));
        StreamResult result = new StreamResult(writer);

        transformer.transform(source, result);

        writer.close();
    }
}