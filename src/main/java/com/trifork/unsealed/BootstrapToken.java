package com.trifork.unsealed;

import static com.trifork.unsealed.XmlUtil.appendChild;
import static com.trifork.unsealed.XmlUtil.declareNamespaces;
import static com.trifork.unsealed.XmlUtil.setAttribute;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.Key;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.time.ZonedDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

import javax.xml.crypto.MarshalException;
import javax.xml.crypto.dsig.XMLSignatureException;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.xpath.XPathExpressionException;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.xml.sax.SAXException;

class Claim {
    final String uri;
    final String value;

    Claim(String uri, String value) {
        this.uri = uri;
        this.value = value;
    }
}

public class BootstrapToken {
    static final String DEFAULT_BST_TO_ID_ENDPOINT = "/sts/services/Bst2Idws";
    static final String DEFAULT_BST_TO_SOSI_ENDPOINT = "/sts/services/BST2SOSI";
    static final String DEFAULT_JWT_TO_ID_ENDPOINT = "/sts/services/JWT2Idws";

    private static final String REQUEST_SECURITY_TOKEN_RESPONSE_XPATH = "/" + NsPrefixes.soap.name() + ":Envelope/"
            + NsPrefixes.soap.name() + ":Body/" + NsPrefixes.wst13.name()
            + ":RequestSecurityTokenResponseCollection/"
            + NsPrefixes.wst13.name() + ":RequestSecurityTokenResponse";

    private static final String BOOTSTRAP_CONDITIONS_XPATH = "/" + NsPrefixes.saml.name() + ":Assertion/"
            + NsPrefixes.saml.name() + ":Conditions";

    private NSPEnv env;
    private X509Certificate certificate;
    private Key privateKey;
    private String xml;
    private String jwt;

    BootstrapToken(NSPEnv env, X509Certificate certificate, Key privateKey, String xml, String jwt) {
        this.env = env;
        this.certificate = certificate;
        this.privateKey = privateKey;
        this.xml = xml;
        this.jwt = jwt;
    }

    /**
     * Invoke SOSI STS to exchange this bootstrap token to an IDWS identity token.
     * @param audience The audience for the identity token, e.g., "https://minlog"
     * @param cpr The CPR of the user
     * @return The identity token
     * @throws IOException
     * @throws InterruptedException
     * @throws NoSuchAlgorithmException
     * @throws InvalidAlgorithmParameterException
     * @throws MarshalException
     * @throws XMLSignatureException
     * @throws XPathExpressionException
     * @throws STSInvocationException
     * @throws ParserConfigurationException
     * @throws SAXException
     */
    public IdentityToken exchangeToIdentityToken(String audience, String cpr)
            throws IOException, InterruptedException,
            NoSuchAlgorithmException, InvalidAlgorithmParameterException,
            MarshalException, XMLSignatureException, XPathExpressionException, STSInvocationException,
            ParserConfigurationException, SAXException {
        return exchangeToIdentityToken(audience, cpr, null);
    }

    /**
     * 
     * Invoke SOSI STS to exchange this bootstrap token to an IDWS identity token that includes verified procuration access. 
     * @param audience The audience for the identity token, e.g., "https://minlog"
     * @param cpr The CPR of the user
     * @param procurationCpr The CPR of the person being the procuration subject
     * @return The identity token
     * @throws IOException
     * @throws InterruptedException
     * @throws NoSuchAlgorithmException
     * @throws InvalidAlgorithmParameterException
     * @throws MarshalException
     * @throws XMLSignatureException
     * @throws XPathExpressionException
     * @throws STSInvocationException
     * @throws ParserConfigurationException
     * @throws SAXException
     */
    public IdentityToken exchangeToIdentityToken(String audience, String cpr, String procurationCpr)
            throws IOException, InterruptedException,
            NoSuchAlgorithmException, InvalidAlgorithmParameterException,
            MarshalException, XMLSignatureException, XPathExpressionException, STSInvocationException,
            ParserConfigurationException, SAXException {

        ArrayList<Claim> claims = new ArrayList<>();

        if (cpr != null) {
            claims.add(new Claim("dk:gov:saml:attribute:CprNumberIdentifier", cpr));
        }

        if (procurationCpr != null) {
            claims.add(new Claim("dk:healthcare:saml:attribute:OnBehalfOf",
                    "urn:dk:healthcare:saml:actThroughProcurationBy:cprNumberIdentifier:"
                            + procurationCpr));
        }

        Element request = createBootstrapExchangeRequest(audience, claims);

        Document doc = request.getOwnerDocument();

        SignatureUtil.sign(doc.getElementById("security"), null,
                new String[] { "#messageID", "#action", "#ts", "#body" }, null, certificate, privateKey,
                false);

        String stsEndpoint = xml != null ? DEFAULT_BST_TO_ID_ENDPOINT : DEFAULT_JWT_TO_ID_ENDPOINT;

        Element response = WSHelper.post(request,
                env.getStsBaseUrl() + stsEndpoint, "Issue");

        XPathContext xpath = new XPathContext(response.getOwnerDocument());

        Element requestSecurityTokenResponse = xpath.findElement(REQUEST_SECURITY_TOKEN_RESPONSE_XPATH);

        Element assertion = xpath.findElement(requestSecurityTokenResponse,
                NsPrefixes.wst13.name() + ":RequestedSecurityToken/" + NsPrefixes.saml.name()
                        + ":Assertion");

        String created = xpath.getText(requestSecurityTokenResponse,
                NsPrefixes.wst13.name() + ":Lifetime/" + NsPrefixes.wsu.name() + ":Created");

        ZonedDateTime createdInstant = ZonedDateTime.parse(created);

        String expires = xpath.getText(requestSecurityTokenResponse,
                NsPrefixes.wst13.name() + ":Lifetime/" + NsPrefixes.wsu.name() + ":Expires");

        ZonedDateTime expiresInstant = ZonedDateTime.parse(expires);

        return new IdentityTokenBuilder().assertion(assertion).audience(audience).created(createdInstant)
                .expires(expiresInstant).build();
    }

    private Element createBootstrapExchangeRequest(String audience, List<Claim> claimsList)
            throws ParserConfigurationException, SAXException, IOException {

        DocumentBuilder docBuilder = XmlUtil.getDocBuilder();

        Document doc = docBuilder.newDocument();

        Element envelope = appendChild(doc, NsPrefixes.soap, "Envelope");

        declareNamespaces(envelope, NsPrefixes.soap, NsPrefixes.ds, NsPrefixes.saml, NsPrefixes.xsi,
                NsPrefixes.wsse,
                NsPrefixes.wst, NsPrefixes.wsa, NsPrefixes.wsu);

        Element soapHeader = appendChild(envelope, NsPrefixes.soap, "Header");

        Element action = appendChild(soapHeader, NsPrefixes.wsa, "Action",
                "http://docs.oasis-open.org/ws-sx/ws-trust/200512/RST/Issue");
        setAttribute(action, NsPrefixes.wsu, "Id", "action", true);

        String msgId = "urn:uuid:" + UUID.randomUUID().toString();
        Element messageID = appendChild(soapHeader, NsPrefixes.wsa, "MessageID", msgId);
        setAttribute(messageID, NsPrefixes.wsu, "Id", "messageID", true);

        Element security = appendChild(soapHeader, NsPrefixes.wsse, "Security");
        setAttribute(security, NsPrefixes.wsu, "Id", "security", true);
        security.setAttribute("mustUnderstand", "1");

        Element timestamp = appendChild(security, NsPrefixes.wsu, "Timestamp");
        setAttribute(timestamp, NsPrefixes.wsu, "Id", "ts", true);
        appendChild(timestamp, NsPrefixes.wsu, "Created",
                XmlUtil.ISO_WITH_MILLIS_FORMATTER.format(Instant.now()));

        Element soapBody = appendChild(envelope, NsPrefixes.soap, "Body");
        setAttribute(soapBody, NsPrefixes.wsu, "Id", "body", true);

        Element requestSecurityToken = appendChild(soapBody, NsPrefixes.wst13, "RequestSecurityToken");
        requestSecurityToken.setAttribute("Context", "urn:uuid:" + UUID.randomUUID().toString());
        appendChild(requestSecurityToken, NsPrefixes.wst13, "TokenType",
                "http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.1#SAMLV2.0");
        appendChild(requestSecurityToken, NsPrefixes.wst13, "RequestType",
                "http://docs.oasis-open.org/ws-sx/ws-trust/200512/Issue");

        Element actAs = appendChild(requestSecurityToken, NsPrefixes.wst14, "ActAs");

        if (xml != null) {
            Element bootstrapToken = docBuilder
                    .parse(new ByteArrayInputStream(xml.getBytes(StandardCharsets.UTF_8)))
                    .getDocumentElement();

            actAs.appendChild(doc.importNode(bootstrapToken, true));
        } else if (jwt != null) {
            Element binarySecurityToken = appendChild(actAs, NsPrefixes.wsse, "BinarySecurityToken");
            binarySecurityToken.setAttribute("ValueType", "urn:ietf:params:oauth:token-type:jwt");
            binarySecurityToken.setTextContent(jwt);
        }

        appendChild(appendChild(appendChild(requestSecurityToken, NsPrefixes.wsp, "AppliesTo"), NsPrefixes.wsa,
                "EndpointReference"), NsPrefixes.wsa, "Address", audience);

        Element claims = appendChild(requestSecurityToken, NsPrefixes.wst13, "Claims");
        claims.setAttribute("Dialect", "http://docs.oasis-open.org/wsfed/authorization/200706/authclaims");

        for (Claim claim : claimsList) {
            Element claimType = appendChild(claims, NsPrefixes.auth, "ClaimType");
            claimType.setAttribute("Uri", claim.uri);
            appendChild(claimType, NsPrefixes.auth, "Value", claim.value);
        }

        return envelope;
    }

    /**
     * Exchange thie bootstrap token to a IDCard of type user
     * @param audience The <code>AppliesTo</code> for the security token request. This has no effect on the returned IDCard
     * @param role The role of the IDCard
     * @param occupation The occupation of the IDCard
     * @param authId The auth id of the IDCard
     * @param systemName The system name of the IDCard
     * @return
     * @throws IOException
     * @throws InterruptedException
     * @throws NoSuchAlgorithmException
     * @throws InvalidAlgorithmParameterException
     * @throws MarshalException
     * @throws XMLSignatureException
     * @throws XPathExpressionException
     * @throws STSInvocationException
     * @throws ParserConfigurationException
     * @throws SAXException
     * @throws UnrecoverableKeyException
     * @throws KeyStoreException
     * @throws CertificateException
     */
    public UserIdCard exchangeToUserIdCard(String audience, String role, String occupation,
            String authId, String systemName)
            throws IOException, InterruptedException,
            NoSuchAlgorithmException, InvalidAlgorithmParameterException,
            MarshalException, XMLSignatureException, XPathExpressionException, STSInvocationException,
            ParserConfigurationException, SAXException, UnrecoverableKeyException, KeyStoreException,
            CertificateException {

        ArrayList<Claim> claims = new ArrayList<>();

        claims.add(new Claim("medcom:ITSystemName", systemName));
        if (role != null) {
            claims.add(new Claim("medcom:UserRole", role)); // e.g. "urn:dk:healthcare:no-role"
        }
        if (authId != null) {
            claims.add(new Claim("medcom:UserAuthorizationCode", authId));
        }
        // claims.add(new Claim("sosi:SubjectNameID", uuid));

        Element request = createBootstrapExchangeRequest(audience, claims);

        Document doc = request.getOwnerDocument();

        SignatureUtil.sign(doc.getElementById("security"), null,
                new String[] { "#messageID", "#action", "#ts", "#body" }, null, certificate, privateKey,
                false);

        String stsEndpoint = DEFAULT_BST_TO_SOSI_ENDPOINT;

        Element response = WSHelper.post(request,
                env.getStsBaseUrl() + stsEndpoint, "Issue");

        XPathContext xpath = new XPathContext(response.getOwnerDocument());

        Element requestSecurityTokenResponse = xpath.findElement(REQUEST_SECURITY_TOKEN_RESPONSE_XPATH);

        Element assertion = xpath.findElement(requestSecurityTokenResponse,
                NsPrefixes.wst13.name() + ":RequestedSecurityToken/" + NsPrefixes.saml.name()
                        + ":Assertion");

        return new IdCardBuilder().assertion(assertion).buildUserIdCard();
    }

    public String getXml() {
        return xml;
    }

    public String getJwt() {
        return jwt;
    }

    public ZonedDateTime getNotOnOrAfter() throws ParserConfigurationException, SAXException, IOException, XPathExpressionException {
        if (xml == null) {
            return null;
        }
        // NOTE: It is suboptimal that we repeatedly parse xml here..
        DocumentBuilder docBuilder = XmlUtil.getDocBuilder();
        Element bootstrapToken = docBuilder
                .parse(new ByteArrayInputStream(xml.getBytes(StandardCharsets.UTF_8)))
                .getDocumentElement();

        XPathContext xpath = new XPathContext(bootstrapToken.getOwnerDocument());

        Element conditions = xpath.findElement(BOOTSTRAP_CONDITIONS_XPATH);

        return ZonedDateTime.parse(conditions.getAttribute("NotOnOrAfter"));
    }
}