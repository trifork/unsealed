package com.trifork.unsealed;

import static com.trifork.unsealed.SamlUtil.addSamlAttribute;
import static com.trifork.unsealed.SamlUtil.addUriTypeSamlAttribute;
import static com.trifork.unsealed.XmlUtil.appendChild;
import static com.trifork.unsealed.XmlUtil.declareNamespaces;
import static com.trifork.unsealed.XmlUtil.getChild;

import java.security.InvalidAlgorithmParameterException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.Base64;
import java.util.logging.Logger;

import javax.xml.crypto.MarshalException;
import javax.xml.crypto.dsig.XMLSignatureException;
import javax.xml.parsers.DocumentBuilderFactory;

import org.w3c.dom.Document;
import org.w3c.dom.Element;

public class BootstrapTokenHelper {

    static final Logger log = Logger.getLogger(BootstrapTokenHelper.class.getName());
    private static final String WELLKNOWN_STS_TEST_ISSUER = "TEST trusted IdP";
    private static final String WELLKNOWN_STS_TEST_ISSUER_HOK = "https://idp.test.nspop.dk";

    static String createCitizenBootstrapToken(X509Certificate idpCert, Key idpPrivateKey, X509Certificate spCert,
            String cpr)
            throws Exception {

        Element assertion = createBootstrapToken(idpCert, idpPrivateKey, spCert,
                "https://bootstrap.sts.nspop.dk/", "dk:gov:saml:attribute:CprNumberIdentifier:" + cpr,
                "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent");

        Element attributeStatement = appendChild(assertion, NsPrefixes.saml.namespaceUri, "AttributeStatement");

        addUriTypeSamlAttribute(attributeStatement, "https://data.gov.dk/model/core/specVersion",
                "OIO-SAML-3.0");

        addUriTypeSamlAttribute(attributeStatement, "https://data.gov.dk/concept/core/nsis/loa", "Substantial");

        addUriTypeSamlAttribute(attributeStatement, "https://data.gov.dk/model/core/eid/cprNumber",
                cpr);

        signAssertion(idpCert, idpPrivateKey, assertion);

        return XmlUtil.node2String(assertion, false, false);
    }

    static String createProfessionalBootstrapToken(X509Certificate idpCert, Key idpPrivateKey,
            X509Certificate spCert,
            String uuid, String cvr, String orgName)
            throws Exception {

        Element assertion = createBootstrapToken(idpCert, idpPrivateKey, spCert, "https://sts.sosi.dk/",
                "urn:uuid:" + uuid, "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent");

        Element attributeStatement = appendChild(assertion, NsPrefixes.saml.namespaceUri, "AttributeStatement");

        addUriTypeSamlAttribute(attributeStatement, "https://data.gov.dk/model/core/specVersion",
                "OIO-SAML-3.0");
        addUriTypeSamlAttribute(attributeStatement, "https://healthcare.data.gov.dk/model/core/specVersion",
                "OIO-SAML-H-3.0");
        addUriTypeSamlAttribute(attributeStatement, "https://data.gov.dk/concept/core/nsis/loa", "High");
        addUriTypeSamlAttribute(attributeStatement,
                "https://data.gov.dk/model/core/eid/professional/uuid/persistent", "urn:uuid:" + uuid);
        addUriTypeSamlAttribute(attributeStatement, "https://data.gov.dk/model/core/eid/professional/cvr", cvr);
        addUriTypeSamlAttribute(attributeStatement, "https://data.gov.dk/model/core/eid/professional/orgName",
                orgName);

        signAssertion(idpCert, idpPrivateKey, assertion);

        return XmlUtil.node2String(assertion, false, false);
    }

    static String createLegacyCitizenBootstrapToken(X509Certificate idpCert, Key idpPrivateKey, String subjectName)
            throws Exception {
        Instant now = Instant.now();

        System.setProperty("com.sun.org.apache.xml.internal.security.ignoreLineBreaks", "true");

        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.setNamespaceAware(true);

        Document doc = dbf.newDocumentBuilder().newDocument();

        Element assertion = appendChild(doc, NsPrefixes.saml, "Assertion");

        assertion.setAttribute("IssueInstant", XmlUtil.ISO_WITHOUT_MILLIS_FORMATTER.format(now));
        assertion.setAttribute("Version", "2.0");
        // String assertionId = "_" + UUID.randomUUID().toString();
        String assertionId = "bst";
        assertion.setAttribute("ID", assertionId);
        assertion.setIdAttribute("ID", true);

        appendChild(assertion, NsPrefixes.saml, "Issuer", WELLKNOWN_STS_TEST_ISSUER);

        Element subject = appendChild(assertion, NsPrefixes.saml, "Subject");
        Element nameID = appendChild(subject, NsPrefixes.saml, "NameID", subjectName);
        nameID.setAttribute("Format", "urn:oasis:names:tc:SAML:1.1:nameid-format:X509SubjectName");

        Element subjectConfirmation = appendChild(subject, NsPrefixes.saml, "SubjectConfirmation");
        subjectConfirmation.setAttribute("Method", "urn:oasis:names:tc:SAML:2.0:cm:bearer");
        Element subjectConfirmationData = appendChild(subjectConfirmation, NsPrefixes.saml,
                "SubjectConfirmationData");
        subjectConfirmationData.setAttribute("NotOnOrAfter",
                XmlUtil.ISO_WITHOUT_MILLIS_FORMATTER.format(now.plusSeconds(3600)));
        subjectConfirmationData.setAttribute("Recipient", "https://sosi");
        Element conditions = appendChild(assertion, NsPrefixes.saml, "Conditions");
        conditions.setAttribute("NotOnOrAfter",
                XmlUtil.ISO_WITHOUT_MILLIS_FORMATTER.format(now.plusSeconds(3600)));
        appendChild(appendChild(conditions, NsPrefixes.saml, "AudienceRestriction"), NsPrefixes.saml,
                "Audience",
                "https://bootstrap.sts.nspop.dk/");
        Element attributeStatement = appendChild(assertion, NsPrefixes.saml, "AttributeStatement");
        Element assurranceLevelAttr = addSamlAttribute(attributeStatement, "Attribute", "3",
                "urn:oasis:names:tc:SAML:2.0:attrname-format:basic");
        assurranceLevelAttr.setAttribute("FriendlyName", "AssuranceLevel");

        signAssertion(idpCert, idpPrivateKey, assertion);

        return XmlUtil.node2String(assertion, false, false);
    }

    private static Element createBootstrapToken(X509Certificate idpCert, Key idpPrivateKey, X509Certificate spCert,
            String audience, String nameId, String nameIdFormat)
            throws Exception {
        Instant now = Instant.now();

        System.setProperty("com.sun.org.apache.xml.internal.security.ignoreLineBreaks", "true");

        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.setNamespaceAware(true);

        Document doc = dbf.newDocumentBuilder().newDocument();

        // Element assertion = appendChild(doc, NsPrefixes.saml, "Assertion");
        Element assertion = doc.createElementNS(NsPrefixes.saml.namespaceUri, "Assertion");
        doc.appendChild(assertion);

        declareNamespaces(assertion, NsPrefixes.xsd, NsPrefixes.xsi);

        assertion.setAttribute("IssueInstant", XmlUtil.ISO_WITHOUT_MILLIS_FORMATTER.format(now));
        assertion.setAttribute("Version", "2.0");
        // String assertionId = "_" + UUID.randomUUID().toString();
        String assertionId = "bst";
        assertion.setAttribute("ID", assertionId);
        assertion.setIdAttribute("ID", true);

        appendChild(assertion, NsPrefixes.saml.namespaceUri, "Issuer", WELLKNOWN_STS_TEST_ISSUER_HOK);

        Element subject = appendChild(assertion, NsPrefixes.saml.namespaceUri, "Subject");

        Element nameID = appendChild(subject, NsPrefixes.saml.namespaceUri, "NameID",
                nameId);
        nameID.setAttribute("Format", nameIdFormat);

        Element subjectConfirmation = appendChild(subject, NsPrefixes.saml.namespaceUri, "SubjectConfirmation");
        subjectConfirmation.setAttribute("Method", "urn:oasis:names:tc:SAML:2.0:cm:holder-of-key");
        Element subjectConfirmationData = appendChild(subjectConfirmation, NsPrefixes.saml.namespaceUri,
                "SubjectConfirmationData");
        subjectConfirmationData.setAttributeNS(NsPrefixes.xsi.namespaceUri, "type",
                "KeyInfoConfirmationDataType");

        Element keyInfo = appendChild(subjectConfirmationData, NsPrefixes.ds, "KeyInfo");

        Element x509Data = appendChild(keyInfo, NsPrefixes.ds, "X509Data");
        appendChild(x509Data, NsPrefixes.ds, "X509Certificate",
                Base64.getEncoder().encodeToString(spCert.getEncoded()));

        Element conditions = appendChild(assertion, NsPrefixes.saml.namespaceUri, "Conditions");
        conditions.setAttribute("NotOnOrAfter",
                XmlUtil.ISO_WITHOUT_MILLIS_FORMATTER.format(now.plusSeconds(3600)));
        appendChild(appendChild(conditions, NsPrefixes.saml.namespaceUri, "AudienceRestriction"),
                NsPrefixes.saml.namespaceUri, "Audience", audience);
        return assertion;

    }


    private static void signAssertion(X509Certificate idpCert, Key idpPrivateKey, Element assertion)
            throws NoSuchAlgorithmException, InvalidAlgorithmParameterException, MarshalException,
            XMLSignatureException {
        String referenceUri = "#" + assertion.getAttribute("ID");
        String signatureId = null;

        Element subject = getChild(assertion, NsPrefixes.saml, "Subject");

        SignatureUtil.sign(assertion, subject, new String[] { referenceUri }, signatureId, idpCert,
                idpPrivateKey,
                true);
    }

}
