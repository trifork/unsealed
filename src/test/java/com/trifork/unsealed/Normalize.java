package com.trifork.unsealed;

import static org.w3c.dom.Node.ELEMENT_NODE;
import static org.w3c.dom.Node.ATTRIBUTE_NODE;
import static org.w3c.dom.Node.TEXT_NODE;
import static org.w3c.dom.Node.CDATA_SECTION_NODE;
import static org.w3c.dom.Node.ENTITY_REFERENCE_NODE;
import static org.w3c.dom.Node.ENTITY_NODE;
import static org.w3c.dom.Node.PROCESSING_INSTRUCTION_NODE;
import static org.w3c.dom.Node.COMMENT_NODE;
import static org.w3c.dom.Node.DOCUMENT_NODE;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileWriter;
import java.io.IOException;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.w3c.dom.Document;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.w3c.dom.Element;
import org.w3c.dom.NamedNodeMap;
import org.xml.sax.SAXException;

public class Normalize {
    public static void main(String[] args) throws ParserConfigurationException, FileNotFoundException, SAXException,
            IOException, TransformerException {

        String inFile = args[0];
        String outFile = args[1];

        // String inFile = "u:/scratch/request.xml";
        // String outFile = "u:/AppData/Local/Temp/req.xml";
        // String inFile = "u:/projects/unsealed/src/test/resources/exchange-bst-request.xml";
        // String outFile = "u:/AppData/Local/Temp/req2.xml";
        
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.setNamespaceAware(true);
        DocumentBuilder docBuilder = dbf.newDocumentBuilder();
        Document source = docBuilder.parse(new FileInputStream(new File(inFile)));

        Document dest = docBuilder.newDocument();

        deepCopy(source.getDocumentElement(), dest);

        dest.normalizeDocument();

        TransformerFactory transformerFactory = TransformerFactory.newInstance();
        Transformer transformer = transformerFactory.newTransformer();
        FileWriter writer = new FileWriter(new File(outFile));
        StreamResult result = new StreamResult(writer);

        transformer.transform(new DOMSource(dest), result);

        writer.close();

    }

    private static void deepCopy(Node source, Node dest) {
        Document destDoc = dest.getNodeType() == DOCUMENT_NODE ? (Document) dest : dest.getOwnerDocument();

        switch (source.getNodeType()) {
            case ELEMENT_NODE:
                Element destElement = destDoc.createElementNS(source.getNamespaceURI(), source.getLocalName());
                dest.appendChild(destElement);

                NodeList childNodes = source.getChildNodes();
                for (int n = 0; n < childNodes.getLength(); n++) {
                    deepCopy(childNodes.item(n), destElement);
                }
                NamedNodeMap attributes = source.getAttributes();
                for (int a = 0; a < attributes.getLength(); a++) {
                    deepCopy(attributes.item(a), destElement);
                }

                break;
            case ATTRIBUTE_NODE:
                if (!"http://www.w3.org/2000/xmlns/".equals(source.getNamespaceURI())) {
                    ((Element) dest).setAttributeNS(source.getNamespaceURI(), source.getLocalName(), source.getNodeValue());
                }
                break;
            case TEXT_NODE:
                dest.appendChild(destDoc.createTextNode(source.getNodeValue()));
                break;
            case CDATA_SECTION_NODE:
                break;
            case ENTITY_REFERENCE_NODE:
                break;
            case ENTITY_NODE:
                break;
            case PROCESSING_INSTRUCTION_NODE:
                break;
            case COMMENT_NODE:
                break;
            case DOCUMENT_NODE:
                break;
        }
    }

}