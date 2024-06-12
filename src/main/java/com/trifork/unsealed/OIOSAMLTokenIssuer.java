package com.trifork.unsealed;

import static com.trifork.unsealed.SamlUtil.addSamlAttribute;
import static com.trifork.unsealed.XmlUtil.appendChild;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.Key;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.Base64;
import java.util.UUID;

import javax.xml.crypto.MarshalException;
import javax.xml.crypto.dsig.XMLSignatureException;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;

import org.w3c.dom.Document;
import org.w3c.dom.Element;

public class OIOSAMLTokenIssuer extends AbstractBuilder<OIOSAMLTokenIssuerParams> {

    public OIOSAMLTokenIssuer() {
        super(new OIOSAMLTokenIssuerParams());
    }

    private OIOSAMLTokenIssuer(OIOSAMLTokenIssuerParams params) {
        super(params);
    }

    public OIOSAMLTokenIssuer idpCertAndKey(CertAndKey idpCertAndKey) {
        OIOSAMLTokenIssuerParams params = this.params.copy();
        params.idpCertAndKey = idpCertAndKey;
        return new OIOSAMLTokenIssuer(params);
    }

    public OIOSAMLTokenIssuer subjectName(String subjectName) {
        OIOSAMLTokenIssuerParams params = this.params.copy();
        params.subjectName = subjectName;
        return new OIOSAMLTokenIssuer(params);
    }

    public OIOSAMLTokenIssuer recipient(String recipient) {
        OIOSAMLTokenIssuerParams params = this.params.copy();
        params.recipient = recipient;
        return new OIOSAMLTokenIssuer(params);
    }

    public OIOSAMLTokenIssuer audience(String audience) {
        OIOSAMLTokenIssuerParams params = this.params.copy();
        params.audience = audience;
        return new OIOSAMLTokenIssuer(params);
    }

    public OIOSAMLTokenIssuer issuer(String issuer) {
        OIOSAMLTokenIssuerParams params = this.params.copy();
        params.issuer = issuer;
        return new OIOSAMLTokenIssuer(params);
    }

    public OIOSAMLTokenIssuer uid(String uid) {
        OIOSAMLTokenIssuerParams params = this.params.copy();
        params.uid = uid;
        return new OIOSAMLTokenIssuer(params);
    }

    public OIOSAMLTokenIssuer pidNumber(String pidNumber) {
        OIOSAMLTokenIssuerParams params = this.params.copy();
        params.pidNumber = pidNumber;
        return new OIOSAMLTokenIssuer(params);
    }

    public OIOSAMLTokenIssuer cvrNumber(String cvrNumber) {
        OIOSAMLTokenIssuerParams params = this.params.copy();
        params.cvrNumber = cvrNumber;
        return new OIOSAMLTokenIssuer(params);
    }

    public OIOSAMLTokenIssuer ridNumber(String ridNumber) {
        OIOSAMLTokenIssuerParams params = this.params.copy();
        params.ridNumber = ridNumber;
        return new OIOSAMLTokenIssuer(params);
    }

    public OIOSAMLTokenIssuer cprNumber(String cprNumber) {
        OIOSAMLTokenIssuerParams params = this.params.copy();
        params.cprNumber = cprNumber;
        return new OIOSAMLTokenIssuer(params);
    }

    public OIOSAMLTokenIssuer surName(String surName) {
        OIOSAMLTokenIssuerParams params = this.params.copy();
        params.surName = surName;
        return new OIOSAMLTokenIssuer(params);
    }

    public OIOSAMLTokenIssuer commonName(String commonName) {
        OIOSAMLTokenIssuerParams params = this.params.copy();
        params.commonName = commonName;
        return new OIOSAMLTokenIssuer(params);
    }

    public OIOSAMLTokenIssuer email(String email) {
        OIOSAMLTokenIssuerParams params = this.params.copy();
        params.email = email;
        return new OIOSAMLTokenIssuer(params);
    }

    public OIOSAMLTokenIssuer organisationName(String organisationName) {
        OIOSAMLTokenIssuerParams params = this.params.copy();
        params.organisationName = organisationName;
        return new OIOSAMLTokenIssuer(params);
    }

    public OIOSAMLToken build()
            throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException,
            UnrecoverableKeyException, InvalidAlgorithmParameterException, MarshalException,
            XMLSignatureException,
            ParserConfigurationException {

        return createSamlToken(params.idpCertAndKey.certificate, params.idpCertAndKey.privateKey);
    }

    private OIOSAMLToken createSamlToken(X509Certificate idpCert, Key idpPrivateKey)
            throws NoSuchAlgorithmException,
            InvalidAlgorithmParameterException, MarshalException, XMLSignatureException,
            UnsupportedEncodingException,
            ParserConfigurationException {

        Instant now = Instant.now();

        System.setProperty("com.sun.org.apache.xml.internal.security.ignoreLineBreaks", "true");

        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.setNamespaceAware(true);

        Document doc = dbf.newDocumentBuilder().newDocument();

        Element assertion = appendChild(doc, NsPrefixes.saml, "Assertion");

        assertion.setAttribute("IssueInstant", XmlUtil.ISO_WITHOUT_MILLIS_FORMATTER.format(now));
        assertion.setAttribute("Version", "2.0");
        String assertionId = "_" + UUID.randomUUID().toString();
        assertion.setAttribute("ID", assertionId);
        assertion.setIdAttribute("ID", true);

        appendChild(assertion, NsPrefixes.saml, "Issuer", params.issuer);

        Element subject = appendChild(assertion, NsPrefixes.saml, "Subject");
        Element nameID = appendChild(subject, NsPrefixes.saml, "NameID", params.subjectName);
        nameID.setAttribute("Format", "urn:oasis:names:tc:SAML:1.1:nameid-format:X509SubjectName");

        Element subjectConfirmation = appendChild(subject, NsPrefixes.saml, "SubjectConfirmation");
        subjectConfirmation.setAttribute("Method", "urn:oasis:names:tc:SAML:2.0:cm:bearer");
        Element subjectConfirmationData = appendChild(subjectConfirmation, NsPrefixes.saml,
                "SubjectConfirmationData");
        subjectConfirmationData.setAttribute("NotOnOrAfter",
                XmlUtil.ISO_WITHOUT_MILLIS_FORMATTER.format(now.plusSeconds(3600)));
        subjectConfirmationData.setAttribute("Recipient", params.recipient);
        Element conditions = appendChild(assertion, NsPrefixes.saml, "Conditions");
        conditions.setAttribute("NotBefore", XmlUtil.ISO_WITHOUT_MILLIS_FORMATTER.format(now));
        conditions.setAttribute("NotOnOrAfter",
                XmlUtil.ISO_WITHOUT_MILLIS_FORMATTER.format(now.plusSeconds(3600)));
        appendChild(appendChild(conditions, NsPrefixes.saml, "AudienceRestriction"), NsPrefixes.saml,
                "Audience",
                params.audience);
        Element attributeStatement = appendChild(assertion, NsPrefixes.saml, "AttributeStatement");

        addSamlAttribute(attributeStatement, OIOSAMLToken.SPEC_VERSION, "DK-SAML-2.0",
                "urn:oasis:names:tc:SAML:2.0:attrname-format:basic");

        if (params.ridNumber != null) {
            addSamlAttribute(attributeStatement, OIOSAMLToken.UID, "CVR:" + params.cvrNumber + "-RID:" + params.ridNumber,
                    "urn:oasis:names:tc:SAML:2.0:attrname-format:basic");
            addSamlAttribute(attributeStatement, OIOSAMLToken.CVR_NUMBER, params.cvrNumber,
                    "urn:oasis:names:tc:SAML:2.0:attrname-format:basic");
            addSamlAttribute(attributeStatement, OIOSAMLToken.RID_NUMBER, params.ridNumber,
                    "urn:oasis:names:tc:SAML:2.0:attrname-format:basic");
        } else {

        }
        addSamlAttribute(attributeStatement, OIOSAMLToken.ASSURANCE_LEVEL, "3",
                "urn:oasis:names:tc:SAML:2.0:attrname-format:basic");
        addSamlAttribute(attributeStatement, OIOSAMLToken.CPR_NUMBER, params.cprNumber,
                "urn:oasis:names:tc:SAML:2.0:attrname-format:basic");
        if (params.surName != null) {
            addSamlAttribute(attributeStatement, OIOSAMLToken.SURNAME, params.surName,
                    "urn:oasis:names:tc:SAML:2.0:attrname-format:basic");
        }
        addSamlAttribute(attributeStatement, OIOSAMLToken.COMMON_NAME, params.commonName,
                "urn:oasis:names:tc:SAML:2.0:attrname-format:basic");
        if (params.email != null) {
            addSamlAttribute(attributeStatement, OIOSAMLToken.EMAIL, params.email,
                    "urn:oasis:names:tc:SAML:2.0:attrname-format:basic");
        }
        if (params.organisationName != null) {
            addSamlAttribute(attributeStatement, OIOSAMLToken.ORGANIZATION_NAME, params.organisationName,
                    "urn:oasis:names:tc:SAML:2.0:attrname-format:basic");
        } else {
            addSamlAttribute(attributeStatement, OIOSAMLToken.ORGANIZATION_NAME,
                    "Ingen organisatorisk tilknytning",
                    "urn:oasis:names:tc:SAML:2.0:attrname-format:basic");
        }

        String bootstrapToken = createBootstrapToken(idpCert, idpPrivateKey);

        String encodedBootstrapToken = Base64.getEncoder()
                .encodeToString(bootstrapToken.getBytes(StandardCharsets.UTF_8));

        addSamlAttribute(attributeStatement, OIOSAMLToken.DISCOVERY_EPR, encodedBootstrapToken,
                "urn:oasis:names:tc:SAML:2.0:attrname-format:basic");

        Element authnStatement = appendChild(assertion, NsPrefixes.saml, "AuthnStatement");
        Element authnContext = appendChild(authnStatement, NsPrefixes.saml, "AuthnContext");
        authnStatement.setAttribute("AuthnInstant", XmlUtil.ISO_WITHOUT_MILLIS_FORMATTER.format(now));
        authnStatement.setAttribute("SessionIndex", assertionId);
        appendChild(authnContext, NsPrefixes.saml, "AuthnContextClassRef",
                "urn:oasis:names:tc:SAML:2.0:ac:classes:X509");

        String referenceUri = "#" + assertionId;
        String signatureId = null;

        doc.normalizeDocument();

        SignatureUtil.sign(assertion, subject, new String[] { referenceUri }, signatureId, idpCert,
                idpPrivateKey,
                true);

        return new OIOSAMLToken(assertion);
    }

    private String createBootstrapToken(X509Certificate idpCert, Key idpPrivateKey)
            throws ParserConfigurationException, NoSuchAlgorithmException,
            InvalidAlgorithmParameterException,
            MarshalException, XMLSignatureException, UnsupportedEncodingException {

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

        // NOTE: We might have to use a different issuer for the bootstrap token in
        // test, because
        // STS trusts a special issuer "TEST trusted IdP" here
        appendChild(assertion, NsPrefixes.saml, "Issuer", params.issuer);

        Element subject = appendChild(assertion, NsPrefixes.saml, "Subject");
        Element nameID = appendChild(subject, NsPrefixes.saml, "NameID", params.subjectName);
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
        Element assurranceLevelAttr = addSamlAttribute(attributeStatement, OIOSAMLToken.ASSURANCE_LEVEL, "3",
                "urn:oasis:names:tc:SAML:2.0:attrname-format:basic");
        assurranceLevelAttr.setAttribute("FriendlyName", "AssuranceLevel");

        String referenceUri = "#" + assertionId;
        String signatureId = null;

        SignatureUtil.sign(assertion, subject, new String[] { referenceUri }, signatureId, idpCert,
                idpPrivateKey,
                true);

        return XmlUtil.node2String(assertion, false, false);
    }

}