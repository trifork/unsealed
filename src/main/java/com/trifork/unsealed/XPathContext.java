package com.trifork.unsealed;

import java.util.Iterator;

import javax.xml.namespace.NamespaceContext;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

public class XPathContext {

    private XPath xPath;
    private Document doc;

    public XPathContext(Document doc) {
        this.doc = doc;
        xPath = XPathFactory.newInstance().newXPath();
        xPath.setNamespaceContext(new NamespaceContext() {

            @Override
            public Iterator<String> getPrefixes(String namespaceURI) {
                return null;
            }

            @Override
            public String getPrefix(String namespaceURI) {
                return null;
            }

            @Override
            public String getNamespaceURI(String prefix) {
                return NsPrefixes.valueOf(prefix).namespaceUri;
            }
        });
    }

    public Element findElement(String path) throws XPathExpressionException {
        return findElement(doc, path);
    }

    public Element findElement(Object context, String path) throws XPathExpressionException {
        NodeList nodes = (NodeList) xPath.evaluate(path, context, XPathConstants.NODESET);
        if (nodes.getLength() == 1) {
            return (Element) nodes.item(0);
        } else if (nodes.getLength() == 0) {
            return null;
        }
        throw new IllegalArgumentException("Expected zero or one results, found " + nodes.getLength());
    }

    public String getText(Object context, String path) throws XPathExpressionException {
        String result = (String) xPath.evaluate(path, context, XPathConstants.STRING);
        return result;
    }
}
