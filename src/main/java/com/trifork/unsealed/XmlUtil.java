package com.trifork.unsealed;

import java.io.ByteArrayOutputStream;
import java.util.HashMap;
import java.util.Map;

import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

public class XmlUtil {
	private static final String XML_ENCODING = "UTF-8";

	public static final String SOAP_ENV = "http://schemas.xmlsoap.org/soap/envelope/";
	public static final String SOSI_SCHEMA = "http://www.sosi.dk/sosi/2006/04/sosi-1.0.xsd";
	public static final String WSU_SCHEMA = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd";
	public static final String WSSE_SCHEMA = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd";
	public static final String WSSE_1_1_SCHEMA = "http://docs.oasis-open.org/wss/oasis-wsswssecurity-secext-1.1.xsd";
	public static final String MEDCOM_SCHEMA = "http://www.medcom.dk/dgws/2006/04/dgws-1.0.xsd";
	public static final String XMLSCHEMAINSTANCE_SCHEMA = "http://www.w3.org/2001/XMLSchema-instance";
	public static final String SAML2ASSERTION_SCHEMA = "urn:oasis:names:tc:SAML:2.0:assertion";
	public static final String SAML2PROTOCOL_SCHEMA = "urn:oasis:names:tc:SAML:2.0:protocol";
	public static final String DSIG_SCHEMA = "http://www.w3.org/2000/09/xmldsig#";
	public static final String SOAP_SCHEMA = "http://schemas.xmlsoap.org/soap/envelope/";
	public static final String XSD_SCHEMA = "http://www.w3.org/2001/XMLSchema";
	public static final String WST_SCHEMA = "http://schemas.xmlsoap.org/ws/2005/02/trust";
	public static final String WST_1_3_SCHEMA = "http://docs.oasis-open.org/ws-sx/ws-trust/200512";
	public static final String WST_1_4_SCHEMA = "http://docs.oasis-open.org/ws-sx/ws-trust/200802";
	public static final String WSA_SCHEMA = "http://schemas.xmlsoap.org/ws/2004/08/addressing";
	public static final String WSA_1_0_SCHEMA = "http://www.w3.org/2005/08/addressing";
	public static final String WSP_SCHEMA = "http://schemas.xmlsoap.org/ws/2004/09/policy";
	public static final String XMLNS_SCHEMA = "http://www.w3.org/2000/xmlns/";
	public static final String LIBERTY_SBF_SCHEMA = "urn:liberty:sb";
	public static final String LIBERTY_SBF_PROFILE_SCHEMA = "urn:liberty:sb:profile";
	public static final String LIBERTY_DISCOVERY_SCHEMA = "urn:liberty:disco:2006-08";
	public static final String LIBERTY_SECURITY_SCHEMA = "urn:liberty:security:2006-08";
	public static final String WSF_AUTH_SCHEMA = "http://docs.oasis-open.org/wsfed/authorization/200706";
	public static final String OIO_BASIC_PRIVILEGES_PROFILE = "http://itst.dk/oiosaml/basic_privilege_profile";

	public static final String NS_SAML = "saml";
	public static final String NS_SAMLP = "samlp";
	public static final String NS_SOAP = "soapenv";
	public static final String NS_XMLNS = "xmlns";
	public static final String NS_WSU = "wsu";
	public static final String NS_WSSE = "wsse";
	public static final String NS_WSSE_1_1 = "wsse11";
	public static final String NS_XSI = "xsi";
	public static final String NS_XSD = "xsd";
	public static final String NS_XS = "xs";
	public static final String NS_SOSI = "sosi";
	public static final String NS_DS = "ds";
	public static final String NS_WST = "wst";
	public static final String NS_WST14 = "wst14";
	public static final String NS_WSA = "wsa";
	public static final String NS_WSP = "wsp";
	public static final String NS_MEDCOM = "medcom";
	public static final String NS_SBF = "sbf";
	public static final String NS_SBFPROFILE = "sbfprofile";
	public static final String NS_LIB_DISCO = "disco";
	public static final String NS_LIB_SEC = "sec";
	public static final String NS_WSF_AUTH = "auth";
	public static final String NS_BPP = "bpp";

	@Deprecated
	public static final String XMLNS_URI = "http://www.w3.org/2000/xmlns/";

	public static final Map<String, String> SOSI_NAMESPACES;
	static {
		SOSI_NAMESPACES = new HashMap<String, String>();
		SOSI_NAMESPACES.put(NS_SOAP, SOAP_SCHEMA);
		SOSI_NAMESPACES.put(NS_DS, DSIG_SCHEMA);
		SOSI_NAMESPACES.put(NS_SAML, SAML2ASSERTION_SCHEMA);
		SOSI_NAMESPACES.put(NS_XSI, XMLSCHEMAINSTANCE_SCHEMA);
		SOSI_NAMESPACES.put(NS_MEDCOM, MEDCOM_SCHEMA);
		SOSI_NAMESPACES.put(NS_WSSE, WSSE_SCHEMA);
		SOSI_NAMESPACES.put(NS_WST, WST_SCHEMA);
		SOSI_NAMESPACES.put(NS_WSA, WSA_SCHEMA);
		SOSI_NAMESPACES.put(NS_WSU, WSU_SCHEMA);
		SOSI_NAMESPACES.put(NS_SOSI, SOSI_SCHEMA);
		SOSI_NAMESPACES.put(NS_XSD, XSD_SCHEMA);
	}

	public static String node2String(Node node, boolean pretty, boolean includeXMLHeader) {

		ByteArrayOutputStream bas = new ByteArrayOutputStream();
		try {
			TransformerFactory factory = TransformerFactory.newInstance();
			Transformer transformer = factory.newTransformer();

			transformer.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "yes");
			transformer.setOutputProperty(OutputKeys.METHOD, "xml");
			transformer.setOutputProperty(OutputKeys.INDENT, (pretty) ? "yes" : "no");
			transformer.setOutputProperty(OutputKeys.ENCODING, XML_ENCODING);
			transformer.setOutputProperty("{http://xml.apache.org/xalan}indent-amount", "4");

			transformer.transform(new DOMSource(node), new StreamResult(bas));

			String str = bas.toString(XML_ENCODING);
			if (includeXMLHeader) {
				str = "<?xml version=\"1.0\" encoding=\"" + XML_ENCODING + "\" ?>" + ((pretty) ? "\n" + str : str);
			}
			return str;
		} catch (RuntimeException e) {
			throw e;
		} catch (Exception e) {
			throw new RuntimeException("Unable to pretty print xml", e);
		}
	}

	public static Element appendChild(Document parent, NsPrefixes nsPrefix, String name) {
		Element child = parent.createElementNS(nsPrefix.namespaceUri, name);
		child.setPrefix(nsPrefix.name());
		parent.appendChild(child);
		return child;
	}

	public static Element appendChild(Element parent, NsPrefixes nsPrefix, String name) {
		Element child = parent.getOwnerDocument().createElementNS(nsPrefix.namespaceUri, name);
		child.setPrefix(nsPrefix.name());
		parent.appendChild(child);
		return child;
	}

	public static Element appendChild(Element parent, NsPrefixes nsPrefix, String name, String textValue) {
		Element child = parent.getOwnerDocument().createElementNS(nsPrefix.namespaceUri, name);
		child.setPrefix(nsPrefix.name());
		child.setTextContent(textValue);
		parent.appendChild(child);
		return child;
	}

	public static String getTextChild(Element parent, NsPrefixes nsPrefix, String name) {
		NodeList childNodes = parent.getChildNodes();
		for (int i = 0; i < childNodes.getLength(); i++) {
			Node item = childNodes.item(0);
			if (nsPrefix.namespaceUri.equals(item.getNamespaceURI()) && name.equals(item.getLocalName())) {
				return item.getTextContent();
			}
		}

		return null;
	}

	public static Element getChild(Element parent, NsPrefixes nsPrefix, String name) {
		NodeList childNodes = parent.getChildNodes();
		for (int i = 0; i < childNodes.getLength(); i++) {
			Node item = childNodes.item(i);
			if (nsPrefix.namespaceUri.equals(item.getNamespaceURI()) && name.equals(item.getLocalName())) {
				return (Element) item;
			}
		}

		return null;
	}

	public static void setAttribute(Element elm, NsPrefixes ns, String name, String value) {
		elm.setAttributeNS(NsPrefixes.wsu.namespaceUri, ns.name() + ":" + name, value);
	}

	public static void setAttribute(Element elm, NsPrefixes ns, String name, String value, boolean isId) {
		setAttribute(elm, ns, name, value);
		if (isId) {
			elm.setIdAttributeNS(NsPrefixes.wsu.namespaceUri, name, true);
		}
	}

}