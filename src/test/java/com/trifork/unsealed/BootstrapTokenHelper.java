package com.trifork.unsealed;

import static com.trifork.unsealed.SamlUtil.addSamlAttribute;
import static com.trifork.unsealed.XmlUtil.appendChild;
import static com.trifork.unsealed.XmlUtil.getChild;

import java.security.InvalidAlgorithmParameterException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.cert.X509Certificate;
import java.time.Instant;
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
