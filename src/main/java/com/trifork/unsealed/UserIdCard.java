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
import javax.xml.xpath.XPathExpressionException;

import org.w3c.dom.Element;

public class UserIdCard extends IdCard {
    private static final String MEDCOM_USER_CIVIL_REGISTRATION_NUMBER = "medcom:UserCivilRegistrationNumber";
    private static final String MEDCOM_USER_OCCUPATION = "medcom:UserOccupation";
    private static final String MEDCOM_USER_ROLE = "medcom:UserRole";
    private static final String MEDCOM_USER_SUR_NAME = "medcom:UserSurName";
    private static final String MEDCOM_USER_GIVEN_NAME = "medcom:UserGivenName";
    private static final String MEDCOM_USER_EMAIL_ADDRESS = "medcom:UserEmailAddress";
    private static final String MEDCOM_USER_AUTHORIZATION_CODE = "medcom:UserAuthorizationCode";
    private static final String MOCES2_ORG_DIVIDER = " // CVR:";
    private static final String ORG_ID = "OID.2.5.4.97";
    private static final Pattern OI_PATTERN = Pattern.compile("NTRDK-(?<Cvr>[0-9]{1,8})");

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

        XPathContext xpathContext = new XPathContext(signedIdCard.getOwnerDocument());

        cpr = getSamlAttribute(xpathContext, signedIdCard, MEDCOM_USER_CIVIL_REGISTRATION_NUMBER);
        role = getSamlAttribute(xpathContext, signedIdCard, MEDCOM_USER_ROLE);
        occupation = getSamlAttribute(xpathContext, signedIdCard, MEDCOM_USER_OCCUPATION);
        authorizationCode = getSamlAttribute(xpathContext, signedIdCard, MEDCOM_USER_AUTHORIZATION_CODE);
        email = getSamlAttribute(xpathContext, signedIdCard, MEDCOM_USER_EMAIL_ADDRESS);
        firstName = getSamlAttribute(xpathContext, signedIdCard, MEDCOM_USER_GIVEN_NAME);
        lastName = getSamlAttribute(xpathContext, signedIdCard, MEDCOM_USER_SUR_NAME);
    }

    protected String getSamlAttribute(XPathContext xpathContext, Element rootElement, String attributeName) {
        String path = "//" + NsPrefixes.saml.name() + ":Assertion/" +
                NsPrefixes.saml.name() + ":AttributeStatement/" + NsPrefixes.saml.name() + ":Attribute[@Name='" + attributeName + "']/" + NsPrefixes.saml.name()
                + ":AttributeValue";
        try {
            Element element = xpathContext.findElement(rootElement, path);
            return element != null ? element.getTextContent() : null;
        } catch (XPathExpressionException e) {
            throw new IllegalArgumentException("Error searching for saml attribute '" + attributeName + "'", e);
        }
    }

    public String getCpr() {
        return cpr;
    }

    public String getRole() {
        return role;
    }

    public String getOccupation() {
        return occupation;
    }

    public String getAuthorizationCode() {
        return authorizationCode;
    }

    public String getEmail() {
        return email;
    }

    public String getFirstName() {
        return firstName;
    }

    public String getLastName() {
        return lastName;
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
        String cn = attributes.get("CN");
        String o = attributes.get("O");

        if (o != null && o.indexOf(MOCES2_ORG_DIVIDER) > 0) {
            // Moces2
            cvr = null;
            int idx1 = o.indexOf(MOCES2_ORG_DIVIDER);
            if (idx1 != -1) {
                organisation = o.substring(0, idx1);
                cvr = o.substring(idx1 + MOCES2_ORG_DIVIDER.length());
            }

            int idx2 = cn.lastIndexOf(" ");
            firstName = cn.substring(0, idx2);
            lastName = cn.substring(idx2 + 1);

            // int idx3 = serialNumber.indexOf("RID:");
            // rid = serialNumber.substring(idx3 + "RID:".length());

        } else {
            // Moces3
            firstName = attributes.get("GIVENNAME");
            lastName = attributes.get("SURNAME");

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

        SamlUtil.addSamlAttribute(userLog, MEDCOM_USER_CIVIL_REGISTRATION_NUMBER, cpr);

        SamlUtil.addSamlAttribute(userLog, MEDCOM_USER_GIVEN_NAME, firstName);

        SamlUtil.addSamlAttribute(userLog, MEDCOM_USER_SUR_NAME, lastName);

        if (email != null) {
            SamlUtil.addSamlAttribute(userLog, MEDCOM_USER_EMAIL_ADDRESS, email);
        }

        if (role != null) {
            SamlUtil.addSamlAttribute(userLog, MEDCOM_USER_ROLE, role);
        }

        if (occupation != null) {
            SamlUtil.addSamlAttribute(userLog, MEDCOM_USER_OCCUPATION, occupation);
        }

        if (authorizationCode != null) {
            SamlUtil.addSamlAttribute(userLog, MEDCOM_USER_AUTHORIZATION_CODE, authorizationCode);
        }
    }
}
