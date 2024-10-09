package com.trifork.unsealed;

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
     * Specify the SP (Service Provider) {@link CertAndKey} (certificate keypair). This is used if the issued bootstrap token is exchanged to an IDWS IdentityToken or a DGWS
     * Idcard.
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

        return new BootstrapToken(params.env, params.spCertAndKey.certificate, params.spCertAndKey.privateKey,
                xml, null);
    }

    /**
     * Issue a bootstrap token for a healthcare professional
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

        return new BootstrapToken(params.env, params.spCertAndKey.certificate, params.spCertAndKey.privateKey,
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
        subjectConfirmation.setAttribute("Method", "urn:oasis:names:tc:SAML:2.0:cm:holder-of-key");
        Element subjectConfirmationData = appendChild(subjectConfirmation, NsPrefixes.saml.namespaceUri,
                "SubjectConfirmationData");
        subjectConfirmationData.setAttributeNS(NsPrefixes.xsi.namespaceUri, "type",
                "KeyInfoConfirmationDataType");

        Element keyInfo = appendChild(subjectConfirmationData, NsPrefixes.ds, "KeyInfo");

        Element x509Data = appendChild(keyInfo, NsPrefixes.ds, "X509Data");
        appendChild(x509Data, NsPrefixes.ds, "X509Certificate",
                Base64.getEncoder().encodeToString(params.spCertAndKey.certificate.getEncoded()));

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