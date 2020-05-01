package com.trifork.unsealed;

import java.io.ByteArrayOutputStream;

import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.w3c.dom.Element;
import org.w3c.dom.Node;

public class XmlUtil {
	private static final String XML_ENCODING = "UTF-8";

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
			if(includeXMLHeader) {
				str = "<?xml version=\"1.0\" encoding=\""+XML_ENCODING+"\" ?>"+((pretty)?"\n"+str:str);
			}
			return str;
		} catch (RuntimeException e) {
			throw e;
		} catch (Exception e) {
			throw new RuntimeException("Unable to pretty print xml", e);
		}
	}

	public static Element appendChild(Element parent, String ns, String name) {
        Element child = parent.getOwnerDocument().createElementNS(ns, name);
        parent.appendChild(child);
        return child;
    }

    public static Element appendChild(Element parent, String ns, String name, String textValue) {
        Element child = parent.getOwnerDocument().createElementNS(ns, name);
        child.setTextContent(textValue);
        parent.appendChild(child);
        return child;
    }

}