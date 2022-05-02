package com.trifork.unsealed;

import static com.trifork.unsealed.XmlUtil.getTextChild;
import static java.util.logging.Level.FINE;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpClient.Redirect;
import java.net.http.HttpClient.Version;
import java.net.http.HttpRequest;
import java.net.http.HttpRequest.BodyPublishers;
import java.net.http.HttpResponse;
import java.net.http.HttpResponse.BodyHandlers;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.xpath.XPathExpressionException;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.xml.sax.SAXException;

public class WSHelper {
    private static final Logger logger = Logger.getLogger(WSHelper.class.getName());

    private static final boolean SUPPORT_LEGACY_SOSISTS_FAULTS = true;
    private static final String FAULT_RESPONSE_XPATH = "/"
            + NsPrefixes.soap.name() + ":Envelope/"
            + NsPrefixes.soap.name() + ":Body/"
            + NsPrefixes.soap.name() + ":Fault";

    public static Element post(Element body, String url, String action)
            throws IOException, InterruptedException, STSInvocationException, ParserConfigurationException {
        return post(XmlUtil.getDocBuilder(), body, url, action);
    }

    public static Element post(DocumentBuilder docBuilder, Element body, String url, String action)
            throws IOException, STSInvocationException, InterruptedException {

        HttpClient client = HttpClient.newBuilder().version(Version.HTTP_1_1).followRedirects(Redirect.NORMAL)
                .connectTimeout(Duration.ofSeconds(20)).build();

        logger.log(Level.FINE, () -> "Request: " + XmlUtil.node2String(body, true, false));

        HttpRequest request = HttpRequest.newBuilder().uri(URI.create(url))
                .header("Content-Type", "text/xml; charset=utf-8").header("SOAPAction", "\"" + action + "\"")
                .POST(BodyPublishers.ofString(XmlUtil.node2String(body, false, false))).build();

        HttpResponse<String> response = client.send(request, BodyHandlers.ofString());

        logger.log(FINE, () -> "Response (status=" + response.statusCode() + "): " + response.body());

        try {
            Document doc = docBuilder.parse(new ByteArrayInputStream(response.body().getBytes(StandardCharsets.UTF_8)));
            Element responseElement = doc.getDocumentElement();

            if (response.statusCode() == 500 || SUPPORT_LEGACY_SOSISTS_FAULTS) {
                XPathContext xpath = new XPathContext(doc);

                Element soapFault = xpath.findElement(FAULT_RESPONSE_XPATH);
                if (soapFault != null) {
                    String faultCode = getTextChild(soapFault, "faultcode");
                    String faultString = getTextChild(soapFault, "faultstring");

                    throw new STSInvocationException(
                            "Got fault from STS, faultcode=" + faultCode + ", faultstring=" + faultString
                                    + ", full response: " + response.body());
                }
            }

            return responseElement;

        } catch (SAXException | XPathExpressionException e) {
            throw new STSInvocationException("Unable to parse response from STS: ", e);
        }
    }
}