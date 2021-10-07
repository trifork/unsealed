package com.trifork.unsealed;

import static com.trifork.unsealed.XmlUtil.appendChild;

import java.security.Key;
import java.security.cert.X509Certificate;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.w3c.dom.Element;

public class UserIdCard extends IdCard {
    private static final Pattern mocesSubjectRegex = Pattern
            .compile("CN=([^\\+ ]+) ([^\\+]+) \\+ SERIALNUMBER=CVR:(\\d+)-RID:(\\d+), O=([^,]+), C=(\\w\\w)");

    private String cpr;
    private String role;
    private String occupation;
    private String authorizationCode;
    private String email;
    private String firstName;
    private String lastName;

    protected UserIdCard(NSPEnv env, String cpr, X509Certificate certificate, Key privateKey, String email, String role,
            String occupation, String authorizationCode, String systemName) {
        super(env, certificate, privateKey, systemName);

        this.cpr = cpr;
        this.role = role;
        this.occupation = occupation;
        this.authorizationCode = authorizationCode;
        this.email = email;
    }

    protected UserIdCard(NSPEnv env, Element signedIdCard) {
        super(env, null, null, null);
        this.signedIdCard = signedIdCard;
    }

    @Override
    protected void extractKeystoreOwnerInfo(X509Certificate cert) {
        String subject = cert.getSubjectDN().getName();
        Matcher matcher = mocesSubjectRegex.matcher(subject);
        if (matcher.matches()) {
            firstName = matcher.group(1);
            lastName = matcher.group(2);
            cvr = matcher.group(3);
            // rid = matcher.group(4);
            organisation = matcher.group(5);

            int idx = organisation.indexOf(" // CVR:");
            if (idx != -1) {
                organisation = organisation.substring(0, idx);
            }
        }
    }

    @Override
    protected void addSubjectAttributes(Element subject) {
        Element nameId = appendChild(subject, NsPrefixes.saml, "NameID", cpr);
        nameId.setAttribute("Format", "medcom:cprnumber");
    }

    @Override
    protected void addTypeSpecificAttributes(Element idCardData, Element assertion) {
        SamlUtil.addSamlAttribute(idCardData, "sosi:IDCardType", "user");

        SamlUtil.addSamlAttribute(idCardData, "sosi:AuthenticationLevel", "4");

        Element userLog = appendChild(assertion, NsPrefixes.saml, "AttributeStatement");
        userLog.setAttribute("id", "UserLog");
        // userLog.setIdAttribute("id", true);

        SamlUtil.addSamlAttribute(userLog, "medcom:UserCivilRegistrationNumber", cpr);

        SamlUtil.addSamlAttribute(userLog, "medcom:UserGivenName", firstName);

        SamlUtil.addSamlAttribute(userLog, "medcom:UserSurName", lastName);

        if (email != null) {
            SamlUtil.addSamlAttribute(userLog, "medcom:UserEmailAddress", email);
        }

        if (role != null) {
            SamlUtil.addSamlAttribute(userLog, "medcom:UserRole", role);
        }

        if (occupation != null) {
            SamlUtil.addSamlAttribute(userLog, "medcom:UserOccupation", occupation);
        }

        if (authorizationCode != null) {
            SamlUtil.addSamlAttribute(userLog, "medcom:AuthorizationCode", authorizationCode);
        }
    }

}
