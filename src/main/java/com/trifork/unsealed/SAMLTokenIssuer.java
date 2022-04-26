package com.trifork.unsealed;

import static com.trifork.unsealed.KeystoreUtil.guessKeystoreType;
import static com.trifork.unsealed.SamlUtil.addSamlAttribute;
import static com.trifork.unsealed.XmlUtil.appendChild;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.Key;
import java.security.KeyStore;
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

public class SAMLTokenIssuer extends AbstractSigningBuilder {
    private String keystoreFromClassPath;
    private String keystoreFromFilePath;
    private InputStream keystoreFromInputStream;
    private KeyStore keystore;
    private String keystoreType;
    private char[] keystorePassword;
    private String subjectName;
    private String recipient;
    private String audience;
    private String issuer;
    private String uid;
    private String pidNumber;
    private String cvrNumber;
    private String ridNumber;
    private String cprNumber;
    private String surName;
    private String commonName;
    private String email;
    private String organisationName;

    public SAMLTokenIssuer() {
    }

    private SAMLTokenIssuer(String keystoreFromClassPath, String keystoreFromFilePath,
            InputStream keystoreFromInputStream, KeyStore keystore, String keystoreType, char[] keystorePassword,
            String subjectName, String recipient,
            String audience, String issuer, String uid, String pidNumber, String cvrNumber,
            String ridNumber, String cprNumber, String surName, String commonName, String email,
            String organisationName) {

        this.keystoreFromClassPath = keystoreFromClassPath;
        this.keystoreFromFilePath = keystoreFromFilePath;
        this.keystoreFromInputStream = keystoreFromInputStream;
        this.keystore = keystore;
        this.keystorePassword = keystorePassword;
        this.subjectName = subjectName;
        this.recipient = recipient;
        this.audience = audience;
        this.issuer = issuer;
        this.uid = uid;
        this.pidNumber = pidNumber;
        this.cvrNumber = cvrNumber;
        this.ridNumber = ridNumber;
        this.cprNumber = cprNumber;
        this.surName = surName;
        this.commonName = commonName;
        this.email = email;
        this.organisationName = organisationName;
    }

    public SAMLTokenIssuer keystoreFromClassPath(String keystoreFromClassPath) {
        return new SAMLTokenIssuer(keystoreFromClassPath, keystoreFromFilePath,
                keystoreFromInputStream, keystore, keystoreType, keystorePassword, subjectName, recipient,
                audience, issuer, uid, pidNumber, cvrNumber,
                ridNumber, cprNumber, surName, commonName, email,
                organisationName);
    }

    public SAMLTokenIssuer keystorePath(String keystorePath) {
        return new SAMLTokenIssuer(keystoreFromClassPath, keystoreFromFilePath,
                keystoreFromInputStream, keystore, keystoreType, keystorePassword, subjectName, recipient,
                audience, issuer, uid, pidNumber, cvrNumber,
                ridNumber, cprNumber, surName, commonName, email,
                organisationName);
    }

    public SAMLTokenIssuer keystoreFromInputStream(InputStream is, String keystoreType) {
        return new SAMLTokenIssuer(keystoreFromClassPath, keystoreFromFilePath,
                keystoreFromInputStream, keystore, keystoreType, keystorePassword, subjectName, recipient,
                audience, issuer, uid, pidNumber, cvrNumber,
                ridNumber, cprNumber, surName, commonName, email,
                organisationName);
    }

    public SAMLTokenIssuer keystorePassword(char[] keystorePassword) {
        return new SAMLTokenIssuer(keystoreFromClassPath, keystoreFromFilePath,
                keystoreFromInputStream, keystore, keystoreType, keystorePassword, subjectName, recipient,
                audience, issuer, uid, pidNumber, cvrNumber,
                ridNumber, cprNumber, surName, commonName, email,
                organisationName);
    }

    public SAMLTokenIssuer subjectName(String subjectName) {
        return new SAMLTokenIssuer(keystoreFromClassPath, keystoreFromFilePath,
                keystoreFromInputStream, keystore, keystoreType, keystorePassword, subjectName, recipient,
                audience, issuer, uid, pidNumber, cvrNumber,
                ridNumber, cprNumber, surName, commonName, email,
                organisationName);
    }

    public SAMLTokenIssuer recipient(String recipient) {
        return new SAMLTokenIssuer(keystoreFromClassPath, keystoreFromFilePath,
                keystoreFromInputStream, keystore, keystoreType, keystorePassword, subjectName, recipient,
                audience, issuer, uid, pidNumber, cvrNumber,
                ridNumber, cprNumber, surName, commonName, email,
                organisationName);
    }

    public SAMLTokenIssuer audience(String audience) {
        return new SAMLTokenIssuer(keystoreFromClassPath, keystoreFromFilePath,
                keystoreFromInputStream, keystore, keystoreType, keystorePassword, subjectName, recipient,
                audience, issuer, uid, pidNumber, cvrNumber,
                ridNumber, cprNumber, surName, commonName, email,
                organisationName);
    }

    public SAMLTokenIssuer issuer(String issuer) {
        return new SAMLTokenIssuer(keystoreFromClassPath, keystoreFromFilePath,
                keystoreFromInputStream, keystore, keystoreType, keystorePassword, subjectName, recipient,
                audience, issuer, uid, pidNumber, cvrNumber,
                ridNumber, cprNumber, surName, commonName, email,
                organisationName);
    }

    public SAMLTokenIssuer uid(String uid) {
        return new SAMLTokenIssuer(keystoreFromClassPath, keystoreFromFilePath,
                keystoreFromInputStream, keystore, keystoreType, keystorePassword, subjectName, recipient,
                audience, issuer, uid, pidNumber, cvrNumber,
                ridNumber, cprNumber, surName, commonName, email,
                organisationName);
    }

    public SAMLTokenIssuer pidNumber(String pidNumber) {
        return new SAMLTokenIssuer(keystoreFromClassPath, keystoreFromFilePath,
                keystoreFromInputStream, keystore, keystoreType, keystorePassword, subjectName, recipient,
                audience, issuer, uid, pidNumber, cvrNumber,
                ridNumber, cprNumber, surName, commonName, email,
                organisationName);
    }

    public SAMLTokenIssuer cvrNumber(String cvrNumber) {
        return new SAMLTokenIssuer(keystoreFromClassPath, keystoreFromFilePath,
                keystoreFromInputStream, keystore, keystoreType, keystorePassword, subjectName, recipient,
                audience, issuer, uid, pidNumber, cvrNumber,
                ridNumber, cprNumber, surName, commonName, email,
                organisationName);
    }

    public SAMLTokenIssuer ridNumber(String ridNumber) {
        return new SAMLTokenIssuer(keystoreFromClassPath, keystoreFromFilePath,
                keystoreFromInputStream, keystore, keystoreType, keystorePassword, subjectName, recipient,
                audience, issuer, uid, pidNumber, cvrNumber,
                ridNumber, cprNumber, surName, commonName, email,
                organisationName);
    }

    public SAMLTokenIssuer cprNumber(String cprNumber) {
        return new SAMLTokenIssuer(keystoreFromClassPath, keystoreFromFilePath,
                keystoreFromInputStream, keystore, keystoreType, keystorePassword, subjectName, recipient,
                audience, issuer, uid, pidNumber, cvrNumber,
                ridNumber, cprNumber, surName, commonName, email,
                organisationName);
    }

    public SAMLTokenIssuer surName(String surName) {
        return new SAMLTokenIssuer(keystoreFromClassPath, keystoreFromFilePath,
                keystoreFromInputStream, keystore, keystoreType, keystorePassword, subjectName, recipient,
                audience, issuer, uid, pidNumber, cvrNumber,
                ridNumber, cprNumber, surName, commonName, email,
                organisationName);
    }

    public SAMLTokenIssuer commonName(String commonName) {
        return new SAMLTokenIssuer(keystoreFromClassPath, keystoreFromFilePath,
                keystoreFromInputStream, keystore, keystoreType, keystorePassword, subjectName, recipient,
                audience, issuer, uid, pidNumber, cvrNumber,
                ridNumber, cprNumber, surName, commonName, email,
                organisationName);
    }

    public SAMLTokenIssuer email(String email) {
        return new SAMLTokenIssuer(keystoreFromClassPath, keystoreFromFilePath,
                keystoreFromInputStream, keystore, keystoreType, keystorePassword, subjectName, recipient,
                audience, issuer, uid, pidNumber, cvrNumber,
                ridNumber, cprNumber, surName, commonName, email,
                organisationName);
    }

    public SAMLTokenIssuer organisationName(String organisationName) {
        return new SAMLTokenIssuer(keystoreFromClassPath, keystoreFromFilePath,
                keystoreFromInputStream, keystore, keystoreType, keystorePassword, subjectName, recipient,
                audience, issuer, uid, pidNumber, cvrNumber,
                ridNumber, cprNumber, surName, commonName, email,
                organisationName);
    }

    public OIOSAMLToken build() throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException,
            UnrecoverableKeyException, InvalidAlgorithmParameterException, MarshalException, XMLSignatureException,
            ParserConfigurationException {

        KeyStore ks = loadKeystore(keystoreType, keystoreFromFilePath);
        X509Certificate certificate = (X509Certificate) ks.getCertificate(ks.aliases().nextElement());

        certificate.checkValidity();

        Key privateKey = ks.getKey(ks.aliases().nextElement(), keystorePassword);

        return createSamlToken(certificate, privateKey);
    }

    private KeyStore loadKeystore(String keystoreTp, String keystoreFromFilePath)
            throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException {
        InputStream keystoreIs;
        KeyStore ks;

        if (keystoreFromInputStream != null) {
            keystoreIs = keystoreFromInputStream;
            if (keystoreType == null) {
                throw new IllegalStateException("KeystoreType must be specified with keystoreFromInputStream");
            }
        } else if (keystoreFromClassPath != null) {
            keystoreIs = Thread.currentThread().getContextClassLoader().getResourceAsStream(keystoreFromClassPath);
            keystoreTp = guessKeystoreType(keystoreFromClassPath);
        } else if (keystoreFromFilePath != null) {
            keystoreIs = new FileInputStream(new File(keystoreFromFilePath));
            keystoreTp = guessKeystoreType(keystoreFromClassPath);
        } else {
            throw new IllegalStateException("No keystore specified");
        }

        ks = KeyStore.getInstance(keystoreTp);
        ks.load(keystoreIs, keystorePassword);

        return ks;
    }

    private OIOSAMLToken createSamlToken(X509Certificate idpCert, Key idpPrivateKey) throws NoSuchAlgorithmException,
            InvalidAlgorithmParameterException, MarshalException, XMLSignatureException, UnsupportedEncodingException,
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

        appendChild(assertion, NsPrefixes.saml, "Issuer", issuer);

        Element subject = appendChild(assertion, NsPrefixes.saml, "Subject");
        Element nameID = appendChild(subject, NsPrefixes.saml, "NameID", subjectName);
        nameID.setAttribute("Format", "urn:oasis:names:tc:SAML:1.1:nameid-format:X509SubjectName");

        Element subjectConfirmation = appendChild(subject, NsPrefixes.saml, "SubjectConfirmation");
        subjectConfirmation.setAttribute("Method", "urn:oasis:names:tc:SAML:2.0:cm:bearer");
        Element subjectConfirmationData = appendChild(subjectConfirmation, NsPrefixes.saml, "SubjectConfirmationData");
        subjectConfirmationData.setAttribute("NotOnOrAfter",
                XmlUtil.ISO_WITHOUT_MILLIS_FORMATTER.format(now.plusSeconds(3600)));
        subjectConfirmationData.setAttribute("Recipient", recipient);
        Element conditions = appendChild(assertion, NsPrefixes.saml, "Conditions");
        conditions.setAttribute("NotBefore", XmlUtil.ISO_WITHOUT_MILLIS_FORMATTER.format(now));
        conditions.setAttribute("NotOnOrAfter", XmlUtil.ISO_WITHOUT_MILLIS_FORMATTER.format(now.plusSeconds(3600)));
        appendChild(appendChild(conditions, NsPrefixes.saml, "AudienceRestriction"), NsPrefixes.saml, "Audience",
                audience);
        Element attributeStatement = appendChild(assertion, NsPrefixes.saml, "AttributeStatement");

        addSamlAttribute(attributeStatement, OIOSAMLToken.SPEC_VERSION, "DK-SAML-2.0",
                "urn:oasis:names:tc:SAML:2.0:attrname-format:basic");

        if (ridNumber != null) {
            addSamlAttribute(attributeStatement, OIOSAMLToken.UID, "CVR:" + cvrNumber + "-RID:" + ridNumber,
                    "urn:oasis:names:tc:SAML:2.0:attrname-format:basic");
            addSamlAttribute(attributeStatement, OIOSAMLToken.CVR_NUMBER, cvrNumber,
                    "urn:oasis:names:tc:SAML:2.0:attrname-format:basic");
            addSamlAttribute(attributeStatement, OIOSAMLToken.RID_NUMBER, ridNumber,
                    "urn:oasis:names:tc:SAML:2.0:attrname-format:basic");
        } else {

        }
        addSamlAttribute(attributeStatement, OIOSAMLToken.ASSURANCE_LEVEL, "3",
                "urn:oasis:names:tc:SAML:2.0:attrname-format:basic");
        addSamlAttribute(attributeStatement, OIOSAMLToken.CPR_NUMBER, cprNumber,
                "urn:oasis:names:tc:SAML:2.0:attrname-format:basic");
        if (surName != null) {
            addSamlAttribute(attributeStatement, OIOSAMLToken.SURNAME, surName,
                    "urn:oasis:names:tc:SAML:2.0:attrname-format:basic");
        }
        addSamlAttribute(attributeStatement, OIOSAMLToken.COMMON_NAME, commonName,
                "urn:oasis:names:tc:SAML:2.0:attrname-format:basic");
        if (email != null) {
            addSamlAttribute(attributeStatement, OIOSAMLToken.EMAIL, email,
                    "urn:oasis:names:tc:SAML:2.0:attrname-format:basic");
        }
        if (organisationName != null) {
            addSamlAttribute(attributeStatement, OIOSAMLToken.ORGANIZATION_NAME, organisationName,
                    "urn:oasis:names:tc:SAML:2.0:attrname-format:basic");
        } else {
            addSamlAttribute(attributeStatement, OIOSAMLToken.ORGANIZATION_NAME, "Ingen organisatorisk tilknytning",
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
        appendChild(authnContext, NsPrefixes.saml, "AuthnContextClassRef", "urn:oasis:names:tc:SAML:2.0:ac:classes:X509");

        String referenceUri = "#" + assertionId;
        String signatureId = null;

        doc.normalizeDocument();

        SignatureUtil.sign(assertion, subject, new String[] { referenceUri }, signatureId, idpCert, idpPrivateKey,
                true);

        return new OIOSAMLToken(assertion);
    }

    private String createBootstrapToken(X509Certificate idpCert, Key idpPrivateKey)
            throws ParserConfigurationException, NoSuchAlgorithmException, InvalidAlgorithmParameterException,
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

        // NOTE: We might have to use a different issuer for the bootstrap token in test, because
        // STS trusts a special issuer "TEST trusted IdP" here
        appendChild(assertion, NsPrefixes.saml, "Issuer", issuer);

        Element subject = appendChild(assertion, NsPrefixes.saml, "Subject");
        Element nameID = appendChild(subject, NsPrefixes.saml, "NameID", subjectName);
        nameID.setAttribute("Format", "urn:oasis:names:tc:SAML:1.1:nameid-format:X509SubjectName");

        Element subjectConfirmation = appendChild(subject, NsPrefixes.saml, "SubjectConfirmation");
        subjectConfirmation.setAttribute("Method", "urn:oasis:names:tc:SAML:2.0:cm:bearer");
        Element subjectConfirmationData = appendChild(subjectConfirmation, NsPrefixes.saml, "SubjectConfirmationData");
        subjectConfirmationData.setAttribute("NotOnOrAfter",
                XmlUtil.ISO_WITHOUT_MILLIS_FORMATTER.format(now.plusSeconds(3600)));
        subjectConfirmationData.setAttribute("Recipient", "https://sosi");
        Element conditions = appendChild(assertion, NsPrefixes.saml, "Conditions");
        conditions.setAttribute("NotOnOrAfter", XmlUtil.ISO_WITHOUT_MILLIS_FORMATTER.format(now.plusSeconds(3600)));
        appendChild(appendChild(conditions, NsPrefixes.saml, "AudienceRestriction"), NsPrefixes.saml, "Audience",
                "https://bootstrap.sts.nspop.dk/");
        Element attributeStatement = appendChild(assertion, NsPrefixes.saml, "AttributeStatement");
        Element assurranceLevelAttr = addSamlAttribute(attributeStatement, "Attribute", "3",
                "urn:oasis:names:tc:SAML:2.0:attrname-format:basic");
        assurranceLevelAttr.setAttribute("FriendlyName", "AssuranceLevel");

        String referenceUri = "#" + assertionId;
        String signatureId = null;

        SignatureUtil.sign(assertion, subject, new String[] { referenceUri }, signatureId, idpCert, idpPrivateKey,
                true);

        return XmlUtil.node2String(assertion, false, false);
    }

}