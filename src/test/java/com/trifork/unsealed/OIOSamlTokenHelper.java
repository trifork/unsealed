package com.trifork.unsealed;

import static com.trifork.unsealed.SamlUtil.addSamlAttribute;
import static com.trifork.unsealed.XmlUtil.appendChild;

import java.security.Key;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.logging.Logger;

import javax.xml.parsers.DocumentBuilderFactory;

import org.w3c.dom.Document;
import org.w3c.dom.Element;

public class OIOSamlTokenHelper {

	static final Logger log = Logger.getLogger(OIOSamlTokenHelper.class.getName());

    static String createSamlToken(X509Certificate idpCert, Key idpPrivateKey, String subjectName)
            throws Exception {

        String recipient = "https://test1.fmk.netic.dk/fmk/saml/SAMLAssertionConsumer";
        String audience = "https://saml.test1.fmk.netic.dk/fmk/";
        
        Instant now = Instant.now();

        System.setProperty("com.sun.org.apache.xml.internal.security.ignoreLineBreaks", "true");

        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.setNamespaceAware(true);

        Document doc = dbf.newDocumentBuilder().newDocument();

        Element assertion = appendChild(doc, NsPrefixes.saml, "Assertion");

        assertion.setAttribute("IssueInstant", XmlUtil.ISO_WITHOUT_MILLIS_FORMATTER.format(now));
        assertion.setAttribute("Version", "2.0");
        // String assertionId = "_" + UUID.randomUUID().toString();
        String assertionId = "ost";
        assertion.setAttribute("ID", assertionId);
        assertion.setIdAttribute("ID", true);

        appendChild(assertion, NsPrefixes.saml, "Issuer", "https://saml.nemlog-in.dk");

        Element subject = appendChild(assertion, NsPrefixes.saml, "Subject");
        Element nameID = appendChild(subject, NsPrefixes.saml, "NameID", subjectName);
        nameID.setAttribute("Format", "urn:oasis:names:tc:SAML:1.1:nameid-format:X509SubjectName");

        Element subjectConfirmation = appendChild(subject, NsPrefixes.saml, "SubjectConfirmation");
        subjectConfirmation.setAttribute("Method", "urn:oasis:names:tc:SAML:2.0:cm:bearer");
        Element subjectConfirmationData = appendChild(subjectConfirmation, NsPrefixes.saml, "SubjectConfirmationData");
        subjectConfirmationData.setAttribute("NotOnOrAfter", XmlUtil.ISO_WITHOUT_MILLIS_FORMATTER.format(now.plusSeconds(3600)));
        subjectConfirmationData.setAttribute("Recipient", recipient);
        Element conditions = appendChild(assertion, NsPrefixes.saml, "Conditions");
        conditions.setAttribute("NotBefore", XmlUtil.ISO_WITHOUT_MILLIS_FORMATTER.format(now));
        conditions.setAttribute("NotOnOrAfter", XmlUtil.ISO_WITHOUT_MILLIS_FORMATTER.format(now.plusSeconds(3600)));
        appendChild(appendChild(conditions, NsPrefixes.saml, "AudienceRestriction"), NsPrefixes.saml, "Audience", audience);
        Element attributeStatement = appendChild(assertion, NsPrefixes.saml, "AttributeStatement");

		addSamlAttribute(attributeStatement, OIOSAMLToken.SPEC_VERSION, "DK-SAML-2.0", "urn:oasis:names:tc:SAML:2.0:attrname-format:basic");
		addSamlAttribute(attributeStatement, OIOSAMLToken.UID, "CVR:20921897-RID:52723247", "urn:oasis:names:tc:SAML:2.0:attrname-format:basic");
		addSamlAttribute(attributeStatement, OIOSAMLToken.CVR_NUMBER, "20921897", "urn:oasis:names:tc:SAML:2.0:attrname-format:basic");
		addSamlAttribute(attributeStatement, OIOSAMLToken.RID_NUMBER, "52723247", "urn:oasis:names:tc:SAML:2.0:attrname-format:basic");
		addSamlAttribute(attributeStatement, OIOSAMLToken.ASSURANCE_LEVEL,  "3", "urn:oasis:names:tc:SAML:2.0:attrname-format:basic");
		addSamlAttribute(attributeStatement, OIOSAMLToken.CPR_NUMBER, "0501792275", "urn:oasis:names:tc:SAML:2.0:attrname-format:basic");
		addSamlAttribute(attributeStatement, OIOSAMLToken.SURNAME,  "Larsen", "urn:oasis:names:tc:SAML:2.0:attrname-format:basic");
		addSamlAttribute(attributeStatement, OIOSAMLToken.COMMON_NAME,  "Lars Larsen", "urn:oasis:names:tc:SAML:2.0:attrname-format:basic");
		addSamlAttribute(attributeStatement, OIOSAMLToken.EMAIL, "fmk-support@trifork.com", "urn:oasis:names:tc:SAML:2.0:attrname-format:basic");
		addSamlAttribute(attributeStatement, OIOSAMLToken.ORGANIZATION_NAME,  "TRIFORK A/S", "urn:oasis:names:tc:SAML:2.0:attrname-format:basic");
		// addSamlAttribute(attributeStatement, OIOSAMLToken.DISCOVERY_EPR, "....", "urn:oasis:names:tc:SAML:2.0:attrname-format:basic");

        Element authnStatement = appendChild(assertion, NsPrefixes.saml, "AuthnStatement");
        Element authnContext = appendChild(authnStatement, NsPrefixes.saml, "AuthnContext");
        authnStatement.setAttribute("AuthnInstant", XmlUtil.ISO_WITHOUT_MILLIS_FORMATTER.format(now));
        appendChild(authnContext, NsPrefixes.saml, "AuthnContextClassRef", "urn:oasis:names:tc:SAML:2.0:cm:bearer");

        String referenceUri = "#" + assertionId;
        String signatureId = null;

        doc.normalizeDocument();

        SignatureUtil.sign(assertion, subject, new String[] { referenceUri }, signatureId, idpCert, idpPrivateKey, true);

        return XmlUtil.node2String(assertion, false, false);
    }




}
