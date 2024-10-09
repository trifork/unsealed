package com.trifork.unsealed;

import static com.trifork.unsealed.XmlUtil.appendChild;

import org.w3c.dom.Element;

public class SamlUtil {

    public static void addSamlAttribute(Element parent, String name, String value) {
        SamlUtil.addSamlAttribute(parent, name, value, null);
    }

    public static Element addSamlAttribute(Element parent, String name, String value, String nameFormat) {
        Element attr = appendChild(parent, NsPrefixes.saml, "Attribute");
        attr.setAttribute("Name", name);
        if (nameFormat != null) {
            attr.setAttribute("NameFormat", nameFormat);
        }
        appendChild(attr, NsPrefixes.saml, "AttributeValue", value);

        return attr;
    }

    public static Element addUriTypeSamlAttribute(Element parent, String name, String value) {
        Element attr = appendChild(parent, NsPrefixes.saml, "Attribute");
        attr.setAttribute("Name", name);

        attr.setAttribute("NameFormat", "urn:oasis:names:tc:SAML:2.0:attrname-format:uri");
        Element attrValue = appendChild(attr, NsPrefixes.saml, "AttributeValue", value);
        attrValue.setAttributeNS(NsPrefixes.xsi.namespaceUri, NsPrefixes.xsi.name() + ":" + "type",
                NsPrefixes.xsd.name() + ":string");

        return attr;
    }

    public static String getSamlAttribute(Element parent, String name) {
        Element attribute = XmlUtil.getChild(parent, NsPrefixes.saml, "Attribute",
                child -> name.equals(child.getAttribute("Name")));
        if (attribute == null) {
            return null;
        }
        return XmlUtil.getTextChild(attribute, NsPrefixes.saml, "AttributeValue");
    }

}
