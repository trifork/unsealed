package com.trifork.unsealed;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Predicate;
import java.util.function.Supplier;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
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
	private static final String XML_ENCODING = StandardCharsets.UTF_8.name();

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
	public static final String WSA_Aug2004_SCHEMA = "http://schemas.xmlsoap.org/ws/2004/08/addressing";
	public static final String WSA_1_0_SCHEMA = "http://www.w3.org/2005/08/addressing";
	public static final String WSP_SCHEMA = "http://schemas.xmlsoap.org/ws/2004/09/policy";
	public static final String XMLNS_SCHEMA = "http://www.w3.org/2000/xmlns/";
	public static final String LIBERTY_SBF_SCHEMA = "urn:liberty:sb";
	public static final String LIBERTY_SBF_PROFILE_SCHEMA = "urn:liberty:sb:profile";
	public static final String LIBERTY_DISCOVERY_SCHEMA = "urn:liberty:disco:2006-08";
	public static final String LIBERTY_SECURITY_SCHEMA = "urn:liberty:security:2006-08";
	public static final String WSF_AUTH_SCHEMA = "http://docs.oasis-open.org/wsfed/authorization/200706";
	public static final String OIO_BASIC_PRIVILEGES_PROFILE = "http://itst.dk/oiosaml/basic_privilege_profile";
	public static final String XENC = "http://www.w3.org/2001/04/xmlenc#";
	public static final String BPP = "http://itst.dk/oiosaml/basic_privilege_profile";
	public static final String SRP = "urn:dk:healthcare:saml:subject_relations_profile:1.1";

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
		// SOSI_NAMESPACES.put(NS_WSA, WSA_SCHEMA);
		SOSI_NAMESPACES.put(NS_WSU, WSU_SCHEMA);
		SOSI_NAMESPACES.put(NS_SOSI, SOSI_SCHEMA);
		SOSI_NAMESPACES.put(NS_XSD, XSD_SCHEMA);
	}

	public static final Map<String, String> URL_TO_JCE;
	static {
		URL_TO_JCE = new HashMap<>();
		URL_TO_JCE.put("http://www.w3.org/2001/04/xmlenc#rsa-1_5", "RSA/ECB/PKCS1Padding");
		URL_TO_JCE.put("http://www.w3.org/2001/04/xmlenc#aes128-cbc", "AES/CBC/ISO10126Padding");
	}

	public static final DateTimeFormatter ISO_WITH_MILLIS_FORMATTER = DateTimeFormatter
			.ofPattern("yyyy-MM-dd'T'HH:mm:ss.SSS'Z'").withZone(ZoneId.of("UTC"));

	public static final DateTimeFormatter ISO_WITHOUT_MILLIS_FORMATTER = DateTimeFormatter
			.ofPattern("yyyy-MM-dd'T'HH:mm:ss'Z'").withZone(ZoneId.of("UTC"));

	private static byte[] bytes;

	public static Supplier<InputStream> node2InputStream(Node node, boolean pretty, boolean includeXMLHeader) {

		return new Supplier<InputStream>() {

			@Override
			public InputStream get() {
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

					return new ByteArrayInputStream(bas.toByteArray());

				} catch (RuntimeException e) {
					throw e;
				} catch (Exception e) {
					throw new RuntimeException("Unable to pretty print xml", e);
				}
			}
		};
	}

	public static String node2String(Node node, boolean pretty, boolean includeXMLHeader) {
		ByteArrayOutputStream bas = new ByteArrayOutputStream();

		node2OutputStream(node, pretty, includeXMLHeader, bas);

		String str = bas.toString(StandardCharsets.UTF_8);
		if (includeXMLHeader) {
			str = "<?xml version=\"1.0\" encoding=\"" + XML_ENCODING + "\" ?>" + ((pretty) ? "\n" + str : str);
		}
		return str;
	}

	public static void node2OutputStream(Node node, boolean pretty, boolean includeXMLHeader, OutputStream os) {

		try (os) {
			TransformerFactory factory = TransformerFactory.newInstance();
			Transformer transformer = factory.newTransformer();

			transformer.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "yes");
			transformer.setOutputProperty(OutputKeys.METHOD, "xml");
			transformer.setOutputProperty(OutputKeys.INDENT, (pretty) ? "yes" : "no");
			transformer.setOutputProperty(OutputKeys.ENCODING, XML_ENCODING);
			transformer.setOutputProperty("{http://xml.apache.org/xalan}indent-amount", "4");

			transformer.transform(new DOMSource(node), new StreamResult(os));

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

	public static Element appendChild(Element parent, String nsUrl, String name) {
		Element child = parent.getOwnerDocument().createElementNS(nsUrl, name);
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

	public static Element appendChild(Element parent, String nsUrl, String name, String textValue) {
		Element child = parent.getOwnerDocument().createElementNS(nsUrl, name);
		child.setTextContent(textValue);
		parent.appendChild(child);
		return child;
	}

	public static String getAttribute(Element elm, NsPrefixes ns, String name) {
		return elm.getAttributeNS(NsPrefixes.wsu.namespaceUri, ns.name() + ":" + name);
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

	public static String getTextChild(Element parent, NsPrefixes nsPrefix, String name) {
		NodeList childNodes = parent.getChildNodes();
		for (int i = 0; i < childNodes.getLength(); i++) {
			Node item = childNodes.item(i);
			if (nsPrefix.namespaceUri.equals(item.getNamespaceURI()) && name.equals(item.getLocalName())) {
				return item.getTextContent();
			}
		}

		return null;
	}

	public static String getTextChild(Element parent, String name) {
		NodeList childNodes = parent.getChildNodes();
		for (int i = 0; i < childNodes.getLength(); i++) {
			Node item = childNodes.item(i);
			if (name.equals(item.getLocalName())) {
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

	public static Element getChild(Element parent, NsPrefixes nsPrefix, String name, Predicate<Element> predicate) {
		NodeList childNodes = parent.getChildNodes();
		for (int i = 0; i < childNodes.getLength(); i++) {
			Node item = childNodes.item(i);
			if (nsPrefix.namespaceUri.equals(item.getNamespaceURI()) && name.equals(item.getLocalName())
					&& predicate.test((Element) item)) {
				return (Element) item;
			}
		}

		return null;
	}

	public static void declareNamespaces(Element element, NsPrefixes... prefixes) {
		for (NsPrefixes prefix : prefixes) {
			element.setAttributeNS("http://www.w3.org/2000/xmlns/", "xmlns:" + prefix.name(), prefix.namespaceUri);
		}
	}

	static DocumentBuilder getDocBuilder() throws ParserConfigurationException {
		// Neither DocumentBuilderFactory nor DocumentBuilder are guarenteed to be
		// thread safe
		DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
		dbf.setNamespaceAware(true);
		return dbf.newDocumentBuilder();
	}

	public static Key decryptKey(Key privateKey, Element encryptedKey, String encryptedKeyEncryptionAlgo, String encryptionAlgo)
			throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException {

		Element encryptedKeyCipherData = getChild(encryptedKey, NsPrefixes.xenc, "CipherData");
		String encryptedKeyCipherValue = getTextChild(encryptedKeyCipherData, NsPrefixes.xenc, "CipherValue");

		byte[] encryptedBytes = Base64.getMimeDecoder().decode(encryptedKeyCipherValue);

		String jce1 = URL_TO_JCE.get(encryptionAlgo);
		String jceKeyAlgorithm = jce1.substring(0, jce1.indexOf('/'));

		String jceAlgorithm = URL_TO_JCE.get(encryptedKeyEncryptionAlgo);

		Cipher c = Cipher.getInstance(jceAlgorithm);
		c.init(Cipher.UNWRAP_MODE, privateKey);
		Key key = c.unwrap(encryptedBytes, jceKeyAlgorithm, Cipher.SECRET_KEY);

		return key;
	}

	public static String decrypt(Key dataEncryptionKey, Element encryptedData, String encryptionAlgo)
			throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException,
			InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {

		String type = encryptedData.getAttribute("Type");

		if (!"http://www.w3.org/2001/04/xmlenc#Element".equals(type)) {
			throw new RuntimeException("EncryptedData was of unsupported type '" + type + "'");
		}

		Element cipherData = getChild(encryptedData, NsPrefixes.xenc, "CipherData");
		String cipherValue = getTextChild(cipherData, NsPrefixes.xenc, "CipherValue");

		byte[] cryptoBytes = Base64.getMimeDecoder().decode(cipherValue);
		
		String jceAlgorithm = URL_TO_JCE.get(encryptionAlgo);

		Cipher cipher = Cipher.getInstance(jceAlgorithm);
		
		int ivLen = cipher.getBlockSize();

		IvParameterSpec iv = new IvParameterSpec(cryptoBytes, 0, ivLen);		

		cipher.init(Cipher.DECRYPT_MODE, dataEncryptionKey, iv);

		bytes = cipher.doFinal(cryptoBytes, ivLen, cryptoBytes.length - ivLen);

		return new String(bytes, StandardCharsets.UTF_8);
	}
}