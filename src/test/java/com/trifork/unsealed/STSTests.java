package com.trifork.unsealed;

import static com.trifork.unsealed.XmlUtil.appendChild;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.io.OutputStream;
import java.security.Key;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.time.temporal.ChronoUnit;
import java.util.logging.ConsoleHandler;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.logging.SimpleFormatter;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.xml.sax.SAXException;

public class STSTests {
    public static final String DEFAULT_STS_ENDPOINT = "http://test2.ekstern-test.nspop.dk:8080/sts/services/NewSecurityTokenService";
    private static final String KEYSTORE_PASSWORD = "Test1234";
    private static final String DS_NS = "http://www.w3.org/2000/09/xmldsig#";
    private static final String SOAPENV_NS = "http://schemas.xmlsoap.org/soap/envelope/";
    private static final String SAML_NS = "urn:oasis:names:tc:SAML:2.0:assertion";
    private static final String WSA_NS = "http://schemas.xmlsoap.org/ws/2004/08/addressing";
    private static final String WSSE_NS = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd";
    private static final String WST_NS = "http://schemas.xmlsoap.org/ws/2005/02/trust";
    private static final String WSU_NS = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd";

    private static final DateTimeFormatter formatter = DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ss'Z'")
            .withZone(ZoneId.of("UTC"));

    @BeforeAll
    static void setup() {
        // System.setProperty("java.util.logging.SimpleFormatter.format",
        // "%1$tY-%1$tm-%1$td %1$tH:%1$tM:%1$tS.%1$tL %4$-7s [%3$s] (%2$s) %5$s
        // %6$s%n");

        final ConsoleHandler consoleHandler = new ConsoleHandler();
        consoleHandler.setLevel(Level.FINEST);
        consoleHandler.setFormatter(new SimpleFormatter());

        final Logger dsig = Logger.getLogger("org.jcp.xml.dsig.internal");
        dsig.setLevel(Level.FINEST);
        dsig.addHandler(consoleHandler);

        final Logger security = Logger.getLogger("com.sun.org.apache.xml.internal.security");
        security.setLevel(Level.FINEST);
        security.addHandler(consoleHandler);

    }

    @Test
    void signIdCard() throws Exception {

        Instant now = Instant.now();
        // Instant now = Instant.from(formatter.parse("2020-04-16T13:52:12Z"));

        System.setProperty("com.sun.org.apache.xml.internal.security.ignoreLineBreaks", "true");

        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.setNamespaceAware(true);
        DocumentBuilder docBuilder = dbf.newDocumentBuilder();
        Document doc = docBuilder.newDocument();

        KeyStore ks = KeyStore.getInstance("PKCS12");
        ks.load(STSTests.class.getResourceAsStream("/LarsLarsen.p12"), KEYSTORE_PASSWORD.toCharArray());
        Certificate certificate = ks.getCertificate(ks.aliases().nextElement());
        Key privateKey = ks.getKey(ks.aliases().nextElement(), KEYSTORE_PASSWORD.toCharArray());

        Element idcard = createUnsignedIdCard(doc, certificate, now);

        OutputStream os = new ByteArrayOutputStream();

        Element requestBody = createSignIdCardRequest(doc, idcard, now);

        doc.appendChild(requestBody);

        // https://stackoverflow.com/questions/43806589/xml-signature-not-validating-when-adding-an-element-explicitly-to-the-document
        // write/read request document workaround
        doc = reloadDocument(docBuilder, doc);
        idcard = doc.getElementById("IDCard");
        requestBody = doc.getDocumentElement();
        // write/read request document workaround

        SignatureUtil.sign(idcard, "#IDCard", "OCESSignature", certificate, privateKey, os);
        // SignatureUtil.sign(idcard, "#IDCard", null, certificate, privateKey, os);

        System.out.println("Request body: " + XmlUtil.node2String(requestBody, true, false));

        writeElementToFile(doc.getElementById("IDCard"), "idcard.xml");

        String response = WSHelper.post(XmlUtil.node2String(requestBody, false, false), DEFAULT_STS_ENDPOINT, "Issue");

        System.out.println("Response: " + response);
    }

    private Document reloadDocument(DocumentBuilder docBuilder, Document doc)
            throws TransformerException, SAXException, IOException, XPathExpressionException {
        ByteArrayOutputStream os = new ByteArrayOutputStream();
        TransformerFactory transformerFactory = TransformerFactory.newInstance();
        Transformer transformer = transformerFactory.newTransformer();

        transformer.transform(new DOMSource(doc), new StreamResult(os));
        Document newDoc = docBuilder.parse(new ByteArrayInputStream(os.toByteArray()));

        XPathFactory xpathFactory = XPathFactory.newInstance();
        XPath xpath = xpathFactory.newXPath();
        Element idcard = (Element) xpath.evaluate("//*[@id='IDCard']", newDoc, XPathConstants.NODE);
        idcard.setIdAttribute("id", true);

        return newDoc;
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
        Element issuer = appendChild(requestSecurityToken, WST_NS, "Issuer");
        appendChild(issuer, WSA_NS, "Address", "TheSOSILibrary");

        return envelope;
    }

    private Element createUnsignedIdCard(Document doc, Certificate certificate, Instant now) throws Exception {
        String cpr = "0501792275";
        String idCardId = "7u5UHS11LRbf8KCFv26tfQ==";

        Element assertion = doc.createElementNS(SAML_NS, "Assertion");

        assertion.setAttribute("IssueInstant", formatter.format(now));
        assertion.setAttribute("Version", "2.0");
        assertion.setAttribute("id", "IDCard");
        assertion.setIdAttribute("id", true);

        appendChild(assertion, SAML_NS, "Issuer", "TheSOSILibrary");
        Element subject = appendChild(assertion, SAML_NS, "Subject");
        Element nameId = appendChild(subject, SAML_NS, "NameID", cpr);
        nameId.setAttribute("Format", "medcom:cprnumber");

        Element subjectConfirmation = appendChild(subject, SAML_NS, "SubjectConfirmation");
        appendChild(subjectConfirmation, SAML_NS, "ConfirmationMethod", "urn:oasis:names:tc:SAML:2.0:cm:holder-of-key");

        Element keyInfo = appendChild(appendChild(subjectConfirmation, SAML_NS, "SubjectConfirmationData"), DS_NS,
                "KeyInfo");

        appendChild(keyInfo, DS_NS, "KeyName", "OCESSignature");
        Element conditions = appendChild(assertion, SAML_NS, "Conditions");
        conditions.setAttribute("NotBefore", formatter.format(now));
        conditions.setAttribute("NotOnOrAfter", formatter.format(now.plus(24, ChronoUnit.HOURS)));

        Element idCardData = appendChild(assertion, SAML_NS, "AttributeStatement");
        idCardData.setAttribute("id", "IDCardData");

        addSamlAttribute(idCardData, "sosi:IDCardID", idCardId);

        addSamlAttribute(idCardData, "sosi:IDCardVersion", "1.0.1");

        addSamlAttribute(idCardData, "sosi:IDCardType", "user");

        addSamlAttribute(idCardData, "sosi:AuthenticationLevel", "4");

        addSamlAttribute(idCardData, "sosi:OCESCertHash", SignatureUtil.getDigestOfCertificate(certificate));

        Element userLog = appendChild(assertion, SAML_NS, "AttributeStatement");
        userLog.setAttribute("id", "UserLog");
        // userLog.setIdAttribute("id", true);

        addSamlAttribute(userLog, "medcom:UserCivilRegistrationNumber", "0501792275");

        addSamlAttribute(userLog, "medcom:UserGivenName", "Lars");

        addSamlAttribute(userLog, "medcom:UserSurName", "Larsen");

        addSamlAttribute(userLog, "medcom:UserEmailAddress", "min.email@adatatest.com");

        addSamlAttribute(userLog, "medcom:UserRole", "7170");

        addSamlAttribute(userLog, "medcom:UserOccupation", "Doctor");

        Element systemLog = appendChild(assertion, SAML_NS, "AttributeStatement");
        systemLog.setAttribute("id", "SystemLog");
        // systemLog.setIdAttribute("id", true);

        addSamlAttribute(systemLog, "medcom:ITSystemName", "Kom Godt i Gang Guider");

        addSamlAttribute(systemLog, "medcom:CareProviderID", "20921897", "medcom:cvrnumber");

        addSamlAttribute(systemLog, "medcom:CareProviderName", "Statens Serum Institut");

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
