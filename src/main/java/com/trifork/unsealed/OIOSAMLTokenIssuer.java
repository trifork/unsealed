package com.trifork.unsealed;

import static com.trifork.unsealed.SamlUtil.addSamlAttribute;
import static com.trifork.unsealed.XmlUtil.appendChild;

import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.Base64;
import java.util.UUID;

import javax.xml.crypto.MarshalException;
import javax.xml.crypto.dsig.XMLSignatureException;
import javax.xml.parsers.DocumentBuilderFactory;

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

    public OIOSAMLTokenIssuer spCert(X509Certificate spCert) {
        OIOSAMLTokenIssuerParams params = this.params.copy();
        params.spCert = spCert;
        return new OIOSAMLTokenIssuer(params);
    }

    public OIOSAMLTokenIssuer bootstrapTokenIssuer(BootstrapTokenIssuer bootstrapTokenIssuer) {
        OIOSAMLTokenIssuerParams params = this.params.copy();
        params.bootstrapTokenIssuer = bootstrapTokenIssuer;
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

    public OIOSAMLTokenIssuer cprUuid(String cprUuid) {
        OIOSAMLTokenIssuerParams params = this.params.copy();
        params.cprUuid = cprUuid;
        return new OIOSAMLTokenIssuer(params);
    }

    public OIOSAMLTokenIssuer profUuid(String profUuid) {
        OIOSAMLTokenIssuerParams params = this.params.copy();
        params.profUuid = profUuid;
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

    public OIOSAMLToken issueForProfessional() throws Exception {

        Element assertion = createSamlToken(params.idpCertAndKey.certificate, params.idpCertAndKey.privateKey);

        Element attributeStatement = appendChild(assertion, NsPrefixes.saml, "AttributeStatement");

        addSamlAttribute(attributeStatement, OIOSAML3Constants.COMMON_NAME, params.commonName,
                "urn:oasis:names:tc:SAML:2.0:attrname-format:uri");

        if (params.email != null) {
            addSamlAttribute(attributeStatement, OIOSAML3Constants.EMAIL, params.email,
                    "urn:oasis:names:tc:SAML:2.0:attrname-format:uri");
        }

        if (params.cprUuid != null) {
            addSamlAttribute(attributeStatement, OIOSAML3Constants.CPR_UUID, params.cprUuid,
                    "urn:oasis:names:tc:SAML:2.0:attrname-format:uri");
        }

        if (params.ridNumber != null) {
            addSamlAttribute(attributeStatement, OIOSAML3Constants.RID_NUMBER, params.ridNumber,
                    "urn:oasis:names:tc:SAML:2.0:attrname-format:basic");
        }

        addSamlAttribute(attributeStatement, OIOSAML3Constants.CVR_NUMBER, params.cvrNumber,
                "urn:oasis:names:tc:SAML:2.0:attrname-format:uri");

        if (params.organisationName != null) {
            addSamlAttribute(attributeStatement, OIOSAML3Constants.ORGANIZATION_NAME, params.organisationName,
                    "urn:oasis:names:tc:SAML:2.0:attrname-format:uri");
        }

        addSamlAttribute(attributeStatement, OIOSAML3Constants.CPR_NUMBER, params.cprNumber,
                "urn:oasis:names:tc:SAML:2.0:attrname-format:uri");

        if (params.profUuid != null) {
            addSamlAttribute(attributeStatement, OIOSAML3Constants.PROF_UUID, params.profUuid,
                    "urn:oasis:names:tc:SAML:2.0:attrname-format:uri");
        }

        addSamlAttribute(attributeStatement, OIOSAML3Constants.SPEC_VERSION, "OIOSAML-H-3.0", // or is it OIO-SAML-3.0 ?
                "urn:oasis:names:tc:SAML:2.0:attrname-format:basic");

        addSamlAttribute(attributeStatement, OIOSAMLToken.ASSURANCE_LEVEL, "3",
                "urn:oasis:names:tc:SAML:2.0:attrname-format:basic");

        BootstrapTokenIssuer bootstrapTokenIssuer = params.bootstrapTokenIssuer;
        if (bootstrapTokenIssuer != null) {
            BootstrapToken bootstrapToken = bootstrapTokenIssuer
                    .spCert(params.spCert)
                    .cpr(params.cprNumber)
                    .cvr(params.cvrNumber)
                    .uuid(params.profUuid)
                    .orgName(params.organisationName)
                    .issueForProfessional();

            String encodedBootstrapToken = Base64.getEncoder()
                    .encodeToString(bootstrapToken.getXml().getBytes(StandardCharsets.UTF_8));

            addSamlAttribute(attributeStatement, OIOSAML3Constants.BOOTSTRAP_TOKEN, encodedBootstrapToken,
                    "urn:oasis:names:tc:SAML:2.0:attrname-format:basic");
        }

        if (params.surName != null) {
            addSamlAttribute(attributeStatement, OIOSAML3Constants.SURNAME, params.surName,
                    "urn:oasis:names:tc:SAML:2.0:attrname-format:basic");
        }

        sign(assertion, params.idpCertAndKey.certificate, params.idpCertAndKey.privateKey);

        return new OIOSAMLToken(null, params.spCert, null, assertion, false);
    }

    public OIOSAMLToken issueForCitizen() throws Exception {

        Element assertion = createSamlToken(params.idpCertAndKey.certificate, params.idpCertAndKey.privateKey);

        Element attributeStatement = appendChild(assertion, NsPrefixes.saml, "AttributeStatement");

        addSamlAttribute(attributeStatement, OIOSAML3Constants.CPR_NUMBER, params.cprNumber,
                "urn:oasis:names:tc:SAML:2.0:attrname-format:uri");

        if (params.pidNumber != null) {
            addSamlAttribute(attributeStatement, OIOSAML3Constants.PID_NUMBER, params.pidNumber,
                    "urn:oasis:names:tc:SAML:2.0:attrname-format:uri");
        }

        addSamlAttribute(attributeStatement, OIOSAML3Constants.COMMON_NAME, params.commonName,
                "urn:oasis:names:tc:SAML:2.0:attrname-format:uri");

        if (params.cprUuid != null) {
            addSamlAttribute(attributeStatement, OIOSAML3Constants.CPR_UUID, params.cprUuid,
                    "urn:oasis:names:tc:SAML:2.0:attrname-format:uri");
        }

        addSamlAttribute(attributeStatement, OIOSAML3Constants.SPEC_VERSION, "OIOSAML-H-3.0", // or is it OIO-SAML-3.0 ?
                "urn:oasis:names:tc:SAML:2.0:attrname-format:basic");

        addSamlAttribute(attributeStatement, OIOSAMLToken.ASSURANCE_LEVEL, "3",
                "urn:oasis:names:tc:SAML:2.0:attrname-format:basic");

        BootstrapTokenIssuer bootstrapTokenIssuer = params.bootstrapTokenIssuer;
        if (bootstrapTokenIssuer != null) {
            BootstrapToken bootstrapToken = bootstrapTokenIssuer
                    .spCert(params.spCert)
                    .cpr(params.cprNumber)
                    .issueForCitizen();

            String encodedBootstrapToken = Base64.getEncoder()
                    .encodeToString(bootstrapToken.getXml().getBytes(StandardCharsets.UTF_8));

            addSamlAttribute(attributeStatement, OIOSAML3Constants.BOOTSTRAP_TOKEN, encodedBootstrapToken,
                    "urn:oasis:names:tc:SAML:2.0:attrname-format:basic");
        }

        if (params.surName != null) {
            addSamlAttribute(attributeStatement, OIOSAML3Constants.SURNAME, params.surName,
                    "urn:oasis:names:tc:SAML:2.0:attrname-format:basic");
        }

        sign(assertion, params.idpCertAndKey.certificate, params.idpCertAndKey.privateKey);

        return new OIOSAMLToken(null, params.spCert, null, assertion, false);
    }

    private Element createSamlToken(X509Certificate idpCert, Key idpPrivateKey)
            throws Exception {

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
        String subjectName = "dk:gov:saml:attribute:CprNumberIdentifier:" + params.cprNumber;
        Element nameID = appendChild(subject, NsPrefixes.saml, "NameID", subjectName);
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

        Element authnStatement = appendChild(assertion, NsPrefixes.saml, "AuthnStatement");
        Element authnContext = appendChild(authnStatement, NsPrefixes.saml, "AuthnContext");
        authnStatement.setAttribute("AuthnInstant", XmlUtil.ISO_WITHOUT_MILLIS_FORMATTER.format(now));
        authnStatement.setAttribute("SessionIndex", assertionId);
        appendChild(authnContext, NsPrefixes.saml, "AuthnContextClassRef",
                "urn:oasis:names:tc:SAML:2.0:ac:classes:X509");

        return assertion;
    }

    private void sign(Element assertion, X509Certificate idpCert, Key idpPrivateKey)
            throws NoSuchAlgorithmException, InvalidAlgorithmParameterException, MarshalException, XMLSignatureException {

        String referenceUri = "#" + assertion.getAttribute("ID");
        String signatureId = null;
        Element subject = XmlUtil.getChild(assertion, NsPrefixes.saml, "Subject");

        assertion.getOwnerDocument().normalizeDocument();

        SignatureUtil.sign(assertion, subject, new String[] { referenceUri }, signatureId, idpCert,
                idpPrivateKey, true);

    }
}