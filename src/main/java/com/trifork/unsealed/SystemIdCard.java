package com.trifork.unsealed;

import static com.trifork.unsealed.XmlUtil.appendChild;

import java.security.Key;
import java.security.cert.X509Certificate;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.w3c.dom.Element;

public class SystemIdCard extends IdCard {
    protected SystemIdCard(NSPEnv env, X509Certificate certificate, Key privateKey, String systemName) {
        super(env, certificate, privateKey, systemName);
    }

    private static final Pattern subjectRegex = Pattern
            .compile(".*O=(.*) // CVR:(\\d+),.*");

    @Override
    protected void extractKeystoreOwnerInfo(X509Certificate cert) {
        String subject = cert.getSubjectDN().getName();

        Matcher matcher = subjectRegex.matcher(subject);
        if (matcher.matches()) {
            organisation = matcher.group(1);
            cvr = matcher.group(2);
        } else {
            throw new IllegalArgumentException("Unexpected subject format in certificate, subject=\"" + subject + "\"");
        }
    }

    @Override
    protected void addSubjectAttributes(Element subject) {
        Element nameId = appendChild(subject, NsPrefixes.saml, "NameID", cvr);
        nameId.setAttribute("Format", "medcom:cvrnumber");
    }

    @Override
    protected void addTypeSpecificAttributes(Element idCardData, Element assertion) {
        addSamlAttribute(idCardData, "sosi:IDCardType", "system");

        addSamlAttribute(idCardData, "sosi:AuthenticationLevel", "3");
    }
    
}
