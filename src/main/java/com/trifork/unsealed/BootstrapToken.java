package com.trifork.unsealed;

import static com.trifork.unsealed.XmlUtil.appendChild;
import static com.trifork.unsealed.XmlUtil.declareNamespaces;
import static com.trifork.unsealed.XmlUtil.setAttribute;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.time.ZonedDateTime;
import java.util.UUID;

import javax.xml.crypto.MarshalException;
import javax.xml.crypto.dsig.XMLSignatureException;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.xpath.XPathExpressionException;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.xml.sax.SAXException;

public class BootstrapToken {
    static final String DEFAULT_BST_TO_ID_ENDPOINT = "/sts/services/Bst2Idws";

    private static final String REQUEST_SECURITY_TOKEN_RESPONSE_XPATH = "/" + NsPrefixes.soap.name() + ":Envelope/"
            + NsPrefixes.soap.name() + ":Body/" + NsPrefixes.wst13.name() + ":RequestSecurityTokenResponseCollection/"
            + NsPrefixes.wst13.name() + ":RequestSecurityTokenResponse";

    private NSPEnv env;

    private X509Certificate certificate;

    private Key privateKey;

    private String xml;

    BootstrapToken(NSPEnv env, X509Certificate certificate, Key privateKey, String xml) {
        this.env = env;
        this.certificate = certificate;
        this.privateKey = privateKey;
        this.xml = xml;
    }

    public IdentityToken exchangeToIdentityToken(String audience, String cpr) throws IOException, InterruptedException,
            NoSuchAlgorithmException, InvalidAlgorithmParameterException,
            MarshalException, XMLSignatureException, XPathExpressionException, STSInvocationException, ParserConfigurationException, SAXException {

        DocumentBuilder docBuilder = XmlUtil.getDocBuilder();
        Element bootstrapToken = docBuilder.parse(new ByteArrayInputStream(xml.getBytes(StandardCharsets.UTF_8)))
                .getDocumentElement();

        Element request = createBootstrapToIdentityTokenRequest(bootstrapToken, audience, cpr);

        Document doc = request.getOwnerDocument();

        SignatureUtil.sign(doc.getElementById("security"), null,
                new String[] { "#messageID", "#action", "#ts", "#body" }, null, certificate, privateKey, false);

        Element response = WSHelper.post(request,
        env.getStsBaseUrl() + DEFAULT_BST_TO_ID_ENDPOINT, "Issue");
                
        XPathContext xpath = new XPathContext(response.getOwnerDocument());

        Element requestSecurityTokenResponse = xpath.findElement(REQUEST_SECURITY_TOKEN_RESPONSE_XPATH);

        Element assertion = xpath.findElement(requestSecurityTokenResponse,
                NsPrefixes.wst13.name() + ":RequestedSecurityToken/" + NsPrefixes.saml.name() + ":Assertion");

        String created = xpath.getText(requestSecurityTokenResponse,
                NsPrefixes.wst13.name() + ":Lifetime/" + NsPrefixes.wsu.name() + ":Created");

        ZonedDateTime createdInstant = ZonedDateTime.parse(created);

        String expires = xpath.getText(requestSecurityTokenResponse,
                NsPrefixes.wst13.name() + ":Lifetime/" + NsPrefixes.wsu.name() + ":Expires");

        ZonedDateTime expiresInstant = ZonedDateTime.parse(expires);

        return new IdentityTokenBuilder().assertion(assertion).audience(audience).created(createdInstant).expires(expiresInstant).build();
    }

    private Element createBootstrapToIdentityTokenRequest(Element bootstrapToken, String audience, String cpr)
            throws ParserConfigurationException {

        DocumentBuilder docBuilder = XmlUtil.getDocBuilder();
        Document doc = docBuilder.newDocument();

        Element envelope = appendChild(doc, NsPrefixes.soap, "Envelope");

        declareNamespaces(envelope, NsPrefixes.soap, NsPrefixes.ds, NsPrefixes.saml, NsPrefixes.xsi, NsPrefixes.wsse,
                NsPrefixes.wst, NsPrefixes.wsa, NsPrefixes.wsu, NsPrefixes.xsd);

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
        appendChild(timestamp, NsPrefixes.wsu, "Created", XmlUtil.ISO_WITH_MILLIS_FORMATTER.format(Instant.now()));

        Element soapBody = appendChild(envelope, NsPrefixes.soap, "Body");
        setAttribute(soapBody, NsPrefixes.wsu, "Id", "body", true);

        Element requestSecurityToken = appendChild(soapBody, NsPrefixes.wst13, "RequestSecurityToken");
        requestSecurityToken.setAttribute("Context", "urn:uuid:" + UUID.randomUUID().toString());
        appendChild(requestSecurityToken, NsPrefixes.wst13, "TokenType",
                "http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.1#SAMLV2.0");
        appendChild(requestSecurityToken, NsPrefixes.wst13, "RequestType",
                "http://docs.oasis-open.org/ws-sx/ws-trust/200512/Issue");

        Element actAs = appendChild(requestSecurityToken, NsPrefixes.wst14, "ActAs");
        actAs.appendChild(doc.importNode(bootstrapToken, true));

        appendChild(appendChild(appendChild(requestSecurityToken, NsPrefixes.wsp, "AppliesTo"), NsPrefixes.wsa,
                "EndpointReference"), NsPrefixes.wsa, "Address", audience);

        Element claims = appendChild(requestSecurityToken, NsPrefixes.wst13, "Claims");
        claims.setAttribute("Dialect", "http://docs.oasis-open.org/wsfed/authorization/200706/authclaims");
        Element claimType = appendChild(claims, NsPrefixes.auth, "ClaimType");
        claimType.setAttribute("Uri", "dk:gov:saml:attribute:CprNumberIdentifier");
        appendChild(claimType, NsPrefixes.auth, "Value", cpr);

        return envelope;
    }

}