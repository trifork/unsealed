package com.trifork.unsealed;

import static com.trifork.unsealed.XmlUtil.appendChild;

import java.security.Key;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collector;

import javax.naming.InvalidNameException;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.Attribute;
import javax.naming.ldap.LdapName;

import org.w3c.dom.Element;

public class SystemIdCard extends IdCard {
    private static final String MOCES2_ORG_DIVIDER = " // CVR:";
    private static final String ORG_ID = "OID.2.5.4.97";
    private static final Pattern OI_PATTERN = Pattern.compile("NTRDK-(?<Cvr>[0-9]{1,8})");

    protected SystemIdCard(NSPEnv env, boolean useLegacyDGWS_1_0, X509Certificate certificate, Key privateKey, String systemName) {
        super(env, useLegacyDGWS_1_0, certificate, privateKey, systemName);
    }

    protected SystemIdCard(NSPEnv env, Element signedIdCard) {
        super(env, signedIdCard);
    }

    protected void extractSamlAttributes(Element signedIdCard, XPathContext xpathContext) {
    }

    protected void extractKeystoreOwnerInfo(X509Certificate cert) {
        String subject = cert.getSubjectDN().getName();

        LdapName ldapName;
        try {
            ldapName = new LdapName(subject);
        } catch (InvalidNameException e) {
            throw new RuntimeException(e);
        }

        HashMap<String, String> attributes = ldapName.getRdns().stream().collect(Collector.of(
                () -> new HashMap<String, String>(),
                (map, rdn) -> {
                    NamingEnumeration<? extends Attribute> en = rdn.toAttributes().getAll();
                    while (en.hasMoreElements()) {
                        Attribute attribute = en.nextElement();
                        try {
                            map.put(attribute.getID(), attribute.get().toString());
                        } catch (NamingException e) {
                            throw new RuntimeException(e);
                        }
                    }
                },
                (map1, map2) -> {
                    map1.putAll(map2);
                    return map1;
                }));

        // String serialNumber = attributes.get("SERIALNUMBER");
        // String cn = attributes.get("CN");
        String o = attributes.get("O");

        if (o != null && o.indexOf(MOCES2_ORG_DIVIDER) != -1) {
            // Moces2
            cvr = null;

            int idx1 = o.indexOf(MOCES2_ORG_DIVIDER);
            if (idx1 != -1) {
                organisation = o.substring(0, idx1);
                cvr = o.substring(idx1 + MOCES2_ORG_DIVIDER.length());
            }

            // int idx3 = serialNumber.indexOf("RID:");
            // rid = serialNumber.substring(idx3 + "RID:".length());

        } else {
            // Moces3
            String orgId = attributes.get(ORG_ID);

            // String uuid = serialNumber.substring(serialNumber.lastIndexOf(":") + 1);

            Matcher oiMatcher = null;
            if (orgId != null) {
                oiMatcher = OI_PATTERN.matcher(orgId);
                if (oiMatcher.find()) {
                    cvr = oiMatcher.group("Cvr");
                }
            }

            organisation = o;
        }
    }

    @Override
    protected void addSubjectAttributes(Element subject) {
        Element nameId = appendChild(subject, NsPrefixes.saml, "NameID", cvr);
        nameId.setAttribute("Format", "medcom:cvrnumber");
    }

    @Override
    protected void addTypeSpecificAttributes(Element idCardData, Element assertion) {
        SamlUtil.addSamlAttribute(idCardData, "sosi:IDCardType", "system");

        SamlUtil.addSamlAttribute(idCardData, "sosi:AuthenticationLevel", "3");
    }

}
