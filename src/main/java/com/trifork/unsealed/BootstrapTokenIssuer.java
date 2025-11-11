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

import javax.xml.crypto.MarshalException;
import javax.xml.crypto.dsig.XMLSignatureException;
import javax.xml.parsers.DocumentBuilderFactory;

import org.w3c.dom.Document;
import org.w3c.dom.Element;

/**
 * BootstrapTokenIssuer is an immutable builder that issues bootstrap tokens for the danish national health infrastructure. Intended for test use, since
 * production bootstrap tokens typically are issued by official IdPs.
 * 
 * @author Jeppe Sommer
 */
public class BootstrapTokenIssuer extends AbstractBuilder<BootstrapTokenIssuerParams> {
    private static final String WELLKNOWN_STS_TEST_ISSUER_HOK = "https://idp.test.nspop.dk";

    /**
     * Create a blank builder instance.
     */
    public BootstrapTokenIssuer() {
        super(new BootstrapTokenIssuerParams());
    }

    private BootstrapTokenIssuer(BootstrapTokenIssuerParams params) {
        super(params);
    }

    /**
     * Specify the NSP environment which will be the context for the issued bootstrap tokens
     * 
     * @param env Either {@link NSPEnv#fromUrl(String)} or one of the enum values of {@link NSPTestEnv}
     * @return A new immutable builder instance that encapsulates the supplied parameter
     */
    public BootstrapTokenIssuer env(NSPEnv env) {
        var params = this.params.copy();

        params.env = env;

        return new BootstrapTokenIssuer(params);
    }

    /**
     * Specify the CPR number of the user
     * 
     * @param cpr
     *            The CPR number
     * @return A new immutable builder instance that encapsulates the supplied parameter
     */
    public BootstrapTokenIssuer cpr(String cpr) {
        var params = this.params.copy();
        params.cpr = cpr;
        return new BootstrapTokenIssuer(params);
    }

    /**
     * Specify the UUID of the user
     * 
     * @param uuid The UUID
     * @return A new immutable builder instance that encapsulates the supplied parameter
     */
    public BootstrapTokenIssuer uuid(String uuid) {
        var params = this.params.copy();
        params.uuid = uuid;
        return new BootstrapTokenIssuer(params);
    }

    /**
     * Specify the CVR number of the users login organisation
     * 
     * @param cvr The CVR number
     * @return A new immutable builder instance that encapsulates the supplied parameter
     */
    public BootstrapTokenIssuer cvr(String cvr) {
        var params = this.params.copy();
        params.cvr = cvr;
        return new BootstrapTokenIssuer(params);
    }

    /**
     * Specify the name of the users login organisation
     * 
     * @param orgName The organisation name
     * @return A new immutable builder instance that encapsulates the supplied parameter
     */
    public BootstrapTokenIssuer orgName(String orgName) {
        var params = this.params.copy();
        params.orgName = orgName;
        return new BootstrapTokenIssuer(params);
    }

    /**
     * Specify the SP (Service Provider) {@link CertAndKey} (certificate keypair). This is used if the issued bootstrap token is exchanged to an IDWS
     * IdentityToken or a DGWS Idcard.
     * 
     * @see BootstrapToken#exchangeToIdentityToken(String, String)
     * @see BootstrapToken#exchangeToIdentityToken(String, String, String)
     * @see BootstrapToken#exchangeToUserIdCard(String, String, String, String, String)
     * 
     * @param spCertAndKey The SP keypair
     * @return
     */
    public BootstrapTokenIssuer spCertAndKey(CertAndKey spCertAndKey) {
        var params = this.params.copy();
        params.spCertAndKey = spCertAndKey;
        return new BootstrapTokenIssuer(params);
    }

    public BootstrapTokenIssuer spCert(X509Certificate spCert) {
        var params = this.params.copy();
        params.spCert = spCert;
        return new BootstrapTokenIssuer(params);
    }

    /**
     * Specify the IdP (Identify Provider) {@link CertAndKey} (certificate keypair). This will be the issuer of issued tokens.
     * 
     * @param idpCertAndKey The IdP keypair
     * @return A new immutable builder instance that encapsulates the supplied parameter
     */
    public BootstrapTokenIssuer idpCertAndKey(CertAndKey idpCertAndKey) {
        var params = this.params.copy();
        params.idpCertAndKey = idpCertAndKey;
        return new BootstrapTokenIssuer(params);
    }

    /**
     * Issue a bootstrap token for a citizen.
     * 
     * @return The issued bootstrap token
     * @throws Exception
     */
    public BootstrapToken issueForCitizen()
            throws Exception {

        Element assertion = createBootstrapToken("https://bootstrap.sts.nspop.dk/", "dk:gov:saml:attribute:CprNumberIdentifier:" + params.cpr,
                "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent");

        Element attributeStatement = appendChild(assertion, NsPrefixes.saml.namespaceUri, "AttributeStatement");

        addUriTypeSamlAttribute(attributeStatement, "https://data.gov.dk/model/core/specVersion",
                "OIO-SAML-3.0");

        addUriTypeSamlAttribute(attributeStatement, "https://data.gov.dk/concept/core/nsis/loa", "Substantial");

        addUriTypeSamlAttribute(attributeStatement, "https://data.gov.dk/model/core/eid/cprNumber",
                params.cpr);

        signAssertion(params.idpCertAndKey.certificate, params.idpCertAndKey.privateKey, assertion);

        String xml = XmlUtil.node2String(assertion, false, false);

        return new BootstrapToken(params.env,
                params.spCertAndKey != null ? params.spCertAndKey.certificate : null,
                params.spCertAndKey != null ? params.spCertAndKey.privateKey : null,
                xml, null);
    }

    /**
     * Issue a bootstrap token for a healthcare professional
     * 
     * @return The issued bootstrap token
     * @throws Exception
     */
    public BootstrapToken issueForProfessional()
            throws Exception {

        Element assertion = createBootstrapToken("https://sts.sosi.dk/",
                "urn:uuid:" + params.uuid, "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent");

        Element attributeStatement = appendChild(assertion, NsPrefixes.saml.namespaceUri, "AttributeStatement");

        addUriTypeSamlAttribute(attributeStatement, "https://data.gov.dk/model/core/specVersion",
                "OIO-SAML-3.0");
        addUriTypeSamlAttribute(attributeStatement, "https://healthcare.data.gov.dk/model/core/specVersion",
                "OIO-SAML-H-3.0");
        addUriTypeSamlAttribute(attributeStatement, "https://data.gov.dk/concept/core/nsis/loa", "High");
        addUriTypeSamlAttribute(attributeStatement,
                "https://data.gov.dk/model/core/eid/professional/uuid/persistent", "urn:uuid:" + params.uuid);
        addUriTypeSamlAttribute(attributeStatement, "https://data.gov.dk/model/core/eid/professional/cvr", params.cvr);
        addUriTypeSamlAttribute(attributeStatement, "https://data.gov.dk/model/core/eid/professional/orgName",
                params.orgName);

        signAssertion(params.idpCertAndKey.certificate, params.idpCertAndKey.privateKey, assertion);

        String xml = XmlUtil.node2String(assertion, false, false);

        return new BootstrapToken(params.env,
                params.spCertAndKey != null ? params.spCertAndKey.certificate : null,
                params.spCertAndKey != null ? params.spCertAndKey.privateKey : null,
                xml, null);
    }

    /**
     * Issue an eHDSI IDWS XUA bootstrap token for a citizen
     * 
     * @return The issued bootstrap token
     * @throws Exception
     */
    public BootstrapToken issueEhdsiForCitizen()
            throws Exception {

        // Not this audience: "https://audience.nspop.dk/ehdsi"?

        Element assertion = createBootstrapToken("https://fmk", "BstSubjectNameTest",
                "urn:oasis:names:tc:SAML:1.1:nameid-format:X509SubjectName");

        // declareNamespaces(assertion, NsPrefixes.hl7v3, NsPrefixes.saml);
        declareNamespaces(assertion, NsPrefixes.saml);

        Element attributeStatement = appendChild(assertion, NsPrefixes.saml.namespaceUri, "AttributeStatement");

        addUriTypeSamlAttribute(attributeStatement, "urn:dk:healthcare:saml:SpecVersion",
                "eHDSI-IDWS-XUA-1.0");

        addUriTypeSamlAttribute(attributeStatement, "dk:gov:saml:attribute:AssuranceLevel", "3");

        addUriTypeSamlAttribute(attributeStatement, "urn:oasis:names:tc:xacml:2.0:resource:resource-id",
                params.cpr + "^^^&1.2.208.176.1.2&ISO");

        addUriTypeSamlAttribute(attributeStatement, "urn:oasis:names:tc:xspa:1.0:subject:subject-id", "Alfonso Gonzalez");

        Element roleAttribute = addSamlAttribute(attributeStatement, "urn:oasis:names:tc:xacml:2.0:subject:role", null);

        // STS doesn't like when Role has a prefix, but fails with "Error validating DkncpBootstrapSamlAssertion: cvc-elt.4.2: Cannot resolve 'CE' to a type definition for element 'hl7v3:Role'"
        // Element roleElement = appendChild((Element)roleAttribute.getFirstChild(), NsPrefixes.hl7v3, "Role");
        Element roleElement = appendChild((Element) roleAttribute.getFirstChild(), NsPrefixes.hl7v3.namespaceUri, "Role");
        roleElement.setAttribute("code", "2221");
        roleElement.setAttribute("codeSystem", "2.16.840.1.113883.2.9.6.2.7");
        roleElement.setAttribute("codeSystemName", "ISCO");
        roleElement.setAttribute("displayName", "Nursing professionals");
        roleElement.setAttributeNS(NsPrefixes.xsi.namespaceUri, "type", "CE");
        // roleElement.setAttributeNS(NsPrefixes.xsi.namespaceUri, "type", NsPrefixes.hl7v3.name() + ":CE");

        addUriTypeSamlAttribute(attributeStatement, "urn:oasis:names:tc:xspa:1.0:subject:organization-id", "urn:oid:1.3.6.1.4.1.44938");

        addUriTypeSamlAttribute(attributeStatement, "urn:ehdsi:names:subject:healthcare-facility-type", "Hospital");

        Element purposeOfUseAttribute = addSamlAttribute(attributeStatement, "urn:oasis:names:tc:xspa:1.0:subject:purposeofuse", null);
        Element purposeOfUseElement = appendChild((Element) purposeOfUseAttribute.getFirstChild(), NsPrefixes.hl7v3.namespaceUri, "PurposeOfUse");
        purposeOfUseElement.setAttribute("code", "TREATMENT");
        purposeOfUseElement.setAttribute("codeSystem", "urn:oasis:names:tc:xspa:1.0");
        purposeOfUseElement.setAttributeNS(NsPrefixes.xsi.namespaceUri, "type", "CE");

        addUriTypeSamlAttribute(attributeStatement, "urn:oasis:names:tc:xspa:1.0:environment:locality", "Klinik am Berg, 83242 Reit im Winkl");

        addUriTypeSamlAttribute(attributeStatement, "urn:dk:healthcare:saml:IssuancePolicy", "urn:dk:ncp:eHDSI-default");

        addUriTypeSamlAttribute(attributeStatement, "urn:dk:healthcare:saml:CountryOfTreatment", "DE");

        signAssertion(params.idpCertAndKey.certificate, params.idpCertAndKey.privateKey, assertion);

        String xml = XmlUtil.node2String(assertion, false, false);

        return new BootstrapToken(params.env,
                params.spCertAndKey != null ? params.spCertAndKey.certificate : null,
                params.spCertAndKey != null ? params.spCertAndKey.privateKey : null,
                xml, null);
    }

    private Element createBootstrapToken(String audience, String nameId, String nameIdFormat)
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
        Element subjectConfirmationData = appendChild(subjectConfirmation, NsPrefixes.saml.namespaceUri,
                "SubjectConfirmationData");

        X509Certificate spCert = params.spCert;
        if (spCert == null && params.spCertAndKey != null) {
            spCert = params.spCertAndKey.certificate;
        }
        if (spCert != null) {
            // Service provider certificate is known, so issue a holder-of-key assertion
            subjectConfirmation.setAttribute("Method", "urn:oasis:names:tc:SAML:2.0:cm:holder-of-key");
            subjectConfirmationData.setAttributeNS(NsPrefixes.xsi.namespaceUri, "type",
                    "KeyInfoConfirmationDataType");

            Element keyInfo = appendChild(subjectConfirmationData, NsPrefixes.ds, "KeyInfo");

            Element x509Data = appendChild(keyInfo, NsPrefixes.ds, "X509Data");
            appendChild(x509Data, NsPrefixes.ds, "X509Certificate",
                    Base64.getEncoder().encodeToString(spCert.getEncoded()));
        } else {
            subjectConfirmation.setAttribute("Method", "urn:oasis:names:tc:SAML:2.0:cm:bearer");
            subjectConfirmationData.setAttribute("NotOnOrAfter",
                    XmlUtil.ISO_WITHOUT_MILLIS_FORMATTER.format(now.plusSeconds(3600)));
            subjectConfirmationData.setAttribute("Recipient", "https://sosi");
        }

        Element conditions = appendChild(assertion, NsPrefixes.saml.namespaceUri, "Conditions");
        conditions.setAttribute("NotOnOrAfter",
                XmlUtil.ISO_WITHOUT_MILLIS_FORMATTER.format(now.plusSeconds(3600)));
        conditions.setAttribute("NotBefore",
                XmlUtil.ISO_WITHOUT_MILLIS_FORMATTER.format(now.minusSeconds(5)));

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