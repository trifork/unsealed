package com.trifork.unsealed;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.time.ZonedDateTime;
import java.util.TimeZone;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

public class IDCardTest extends AbstractTest {
    private static final String KEYSTORE_PASSWORD = "Test1234";
    private static CertAndKey moces3CertAndKey;

    @BeforeAll
    static void loadKeystore() throws Exception {
        moces3CertAndKey = new KeyStoreLoader().fromClassPath("Lars_Larsen_prodben.p12").password(KEYSTORE_PASSWORD.toCharArray()).load();
    }

    @Disabled
    @Test
    void canSignMoces2IdCard() throws Exception {

        IdCard idCard = new IdCardBuilder()
                .env(NSPTestEnv.TEST1_CNSP)
                .certAndKey(new KeyStoreLoader().fromClassPath("TRIFORK AS - Lars Larsen.p12").password(KEYSTORE_PASSWORD.toCharArray()).load())
                .cpr("0501792275")
                .role("role")
                .occupation("occupation")
                .authorizationCode("authid")
                .systemName("systemname")
                .buildUserIdCard();

        idCard.sign();

        idCard.validate();
    }

    @Test
    void canSignIdCard() throws Exception {

        IdCard idCard = new IdCardBuilder()
                .env(NSPTestEnv.TEST1_CNSP)
                .certAndKey(moces3CertAndKey)
                .cpr("0501792275")
                .role("role")
                .occupation("occupation")
                .authorizationCode("J0184")
                .systemName("systemname")
                .buildUserIdCard();

        idCard.sign();

        idCard.validate();
    }

    @Test
    void canSignIdCardWithoutCpr() throws Exception {
        // If no cpr is specified, STS is kind enough to look it up
        UserIdCard idCard = new IdCardBuilder()
                .env(NSPTestEnv.TEST1_CNSP)
                .certAndKey(moces3CertAndKey)
                .role("urn:dk:healthcare:no-role")
                .systemName("systemname")
                .buildUserIdCard();

        idCard.sign();

        assertEquals("0501792275", idCard.getCpr());

        idCard.validate();
    }

    @Test
    @Disabled
    void canSignMoces2SystemIdCard() throws Exception {

        IdCard idCard = new IdCardBuilder()
                .env(NSPTestEnv.TEST1_CNSP)
                .certAndKey(new KeyStoreLoader().fromClassPath("FMKOnlineBilletOmv-T.jks").password(KEYSTORE_PASSWORD.toCharArray()).load())
                .systemName("systemname")
                .buildSystemIdCard();

        idCard.sign();

        assertEquals("TEST1-NSP-STS", idCard.getIssuer());
        String subjectName = idCard.getSubjectName();
        assertNotNull(subjectName);

        Document doc = XmlUtil.getDocBuilder().newDocument();

        Element copy = idCard.serialize2DOMDocument(doc);
        doc.appendChild(copy);

        String serialized = XmlUtil.node2String(doc, true, false);

        assertTrue(serialized.contains("Assertion"));

        ZonedDateTime notBefore = idCard.getNotBefore();
        assertTrue(notBefore.isBefore(ZonedDateTime.now()));

        ZonedDateTime notOnOrAfter = idCard.getNotOnOrAfter();
        assertTrue(notOnOrAfter.isAfter(ZonedDateTime.now()));

        idCard.validate();
    }

    @Test
    void canSignSystemIdCard() throws Exception {

        IdCard idCard = new IdCardBuilder()
                .env(NSPTestEnv.TEST1_CNSP)
                .certAndKey(new KeyStoreLoader().fromClassPath("FMKOnlineBilletOmv-T_OCES3.p12").password(KEYSTORE_PASSWORD.toCharArray()).load())
                .systemName("systemname")
                .buildSystemIdCard();

        idCard.sign();

        assertEquals("TEST1-NSP-STS", idCard.getIssuer());
        String subjectName = idCard.getSubjectName();
        assertNotNull(subjectName);

        Document doc = XmlUtil.getDocBuilder().newDocument();

        Element copy = idCard.serialize2DOMDocument(doc);
        doc.appendChild(copy);

        String serialized = XmlUtil.node2String(doc, true, false);

        assertTrue(serialized.contains("Assertion"));

        ZonedDateTime notBefore = idCard.getNotBefore();
        assertTrue(notBefore.isBefore(ZonedDateTime.now()));

        ZonedDateTime notOnOrAfter = idCard.getNotOnOrAfter();
        assertTrue(notOnOrAfter.isAfter(ZonedDateTime.now()));

        idCard.validate();
    }

    @Test
    void canSignIdCardUsingLegacySTSService() throws Exception {

        IdCard idCard = new IdCardBuilder()
                .env(NSPTestEnv.TEST1_CNSP)
                .certAndKey(moces3CertAndKey)
                .cpr("0501792275")
                .role("role")
                .occupation("occupation")
                .authorizationCode("J0184")
                .systemName("systemname")
                .buildUserIdCard();

        idCard.signUsingLegacySTSService();

        idCard.validate();
    }

    @Test
    void canSignDGWS_1_0_IdCard() throws Exception {

        TimeZone defaultTimeZone = TimeZone.getDefault();
        try {
            // Legacy IDWS 1.0 IdCard use date/time with no timezone, and SOSI STS is placed in Denmark. But when building with
            // GitHup Actions, we are in another timezone. Set timezone to Europe/Copenhagen to align with STS just for this test. 
            TimeZone.setDefault(TimeZone.getTimeZone("Europe/Copenhagen"));
            
            IdCard idCard = new IdCardBuilder()
            .uselegacyDGWS_1_0(true)
            .env(NSPTestEnv.TEST1_CNSP)
            .certAndKey(moces3CertAndKey)
            .cpr("0501792275")
            .role("role")
            .occupation("occupation")
            .authorizationCode("J0184")
            .systemName("systemname")
            .buildUserIdCard();
            
            idCard.sign();
            
            idCard.validate();
        } finally {
            // Switch back to jvm default timezone..
            TimeZone.setDefault(defaultTimeZone);
        }
    }

    @Disabled
    @Test
    void canExchangeMoces2IdCardToOIOSAMLToken() throws Exception {

        IdCard idCard = new IdCardBuilder()
                .env(NSPTestEnv.TEST1_CNSP)
                .certAndKey(new KeyStoreLoader().fromClassPath("TRIFORK AS - Lars Larsen.p12").password(KEYSTORE_PASSWORD.toCharArray()).load())
                .cpr("0501792275")
                .role("role")
                .occupation("occupation")
                .systemName("systemname")
                .buildUserIdCard();

        idCard.sign();

        OIOSAMLToken samlToken = idCard.exchangeToOIOSAMLToken("https://saml.test1.fmk.netic.dk/fmk/");
        assertNotNull(samlToken);

        if (samlToken.isEncrypted()) {
            Element encryptedAssertion = samlToken.getAssertion();
            assertEquals("EncryptedAssertion", encryptedAssertion.getLocalName());
            assertEquals(NsPrefixes.saml.namespaceUri, encryptedAssertion.getNamespaceURI());

            OIOSAMLToken samlToken1 = new OIOSAMLTokenBuilder().env(NSPTestEnv.TEST1_CNSP)
                    .spCertAndKey(new KeyStoreLoader().fromClassPath("FMKOnlineBilletOmv-T_OCES3.p12").password(KEYSTORE_PASSWORD.toCharArray()).load())
                    .assertion(samlToken.getAssertion()).build();

            samlToken1.decrypt();

            assertEquals("Lars Larsen", samlToken1.getCommonName());

        } else {
            assertEquals("Lars Larsen", samlToken.getCommonName());
        }

    }

    @Test
    void canExchangeIdCardToOIOSAMLToken() throws Exception {

        IdCard idCard = new IdCardBuilder()
                .env(NSPTestEnv.TEST1_CNSP)
                .certAndKey(moces3CertAndKey)
                .cpr("0501792275")
                .role("role")
                .occupation("occupation")
                .systemName("systemname")
                .buildUserIdCard();

        idCard.sign();

        OIOSAMLToken samlToken = idCard.exchangeToOIOSAMLToken("https://saml.test1.fmk.netic.dk/fmk/");
        assertNotNull(samlToken);

        if (samlToken.isEncrypted()) {
            Element encryptedAssertion = samlToken.getAssertion();
            assertEquals("EncryptedAssertion", encryptedAssertion.getLocalName());
            assertEquals(NsPrefixes.saml.namespaceUri, encryptedAssertion.getNamespaceURI());

            OIOSAMLToken samlToken1 = new OIOSAMLTokenBuilder().env(NSPTestEnv.TEST1_CNSP)
                    .spCertAndKey(new KeyStoreLoader().fromClassPath("FMKOnlineBilletOmv-T_OCES3.p12").password(KEYSTORE_PASSWORD.toCharArray()).load())
                    .assertion(samlToken.getAssertion()).build();

            samlToken1.decrypt();

            assertEquals("Lars Larsen", samlToken1.getCommonName());

        } else {
            assertEquals("Lars Larsen", samlToken.getCommonName());
        }

    }

    @Test
    void willFailOnInvalidSignature() throws Exception {

        IdCard idCard = new IdCardBuilder()
                .env(NSPTestEnv.TEST1_CNSP)
                .certAndKey(moces3CertAndKey)
                .cpr("0501792275")
                .role("role")
                .occupation("occupation")
                .authorizationCode("J0184")
                .systemName("systemname")
                .buildUserIdCard();

        idCard.sign();

        idCard.validate();

        Element assertion = idCard.getAssertion();

        // Find the userGivenName AttributeValue
        XPathContext xpath = new XPathContext(assertion.getOwnerDocument());
        Element userGivenName = xpath
                .findElement("//" + NsPrefixes.saml.name() + ":Attribute[@Name='medcom:UserGivenName']/"
                        + NsPrefixes.saml.name() + ":AttributeValue");

        // Change user given name. This should provoke a validation exception
        userGivenName.setTextContent("Peter");

        assertThrows(ValidationException.class, () -> {
            idCard.validate();
        });
    }

    @Test
    void canBuildIdCardFromXml() throws Exception {

        IdCard idCard = new IdCardBuilder()
                .env(NSPTestEnv.TEST1_CNSP)
                .certAndKey(moces3CertAndKey)
                .cpr("0501792275")
                .role("role")
                .occupation("occupation")
                .authorizationCode("J0184")
                .systemName("systemname")
                .buildUserIdCard();

        idCard.sign();

        idCard.validate();

        Element assertion = idCard.getAssertion();

        String xml = XmlUtil.node2String(assertion, false, false);

        UserIdCard userIdCard = new IdCardBuilder()
                .env(NSPTestEnv.TEST1_CNSP)
                .fromXml(xml)
                .buildUserIdCard();

        userIdCard.validate();

        assertEquals("systemname", userIdCard.getItSystemName());
        assertEquals("96908409", userIdCard.getCareProviderId());
        assertEquals("medcom:cvrnumber", userIdCard.getCareProviderIdNameFormat());
        assertEquals("Testorganisation nr. 96908409", userIdCard.getCareProviderName());
        assertEquals(4, userIdCard.getAuthLevel());
        assertNotNull(userIdCard.getIdCardId());
        assertEquals(idCard.getIdCardId(), userIdCard.getIdCardId());
        assertEquals("1.0.1", userIdCard.getDGWSVersion());
    }

    @Test
    void canAutoDetectUserIdCardType() throws Exception {

        IdCard userIdCard = new IdCardBuilder()
                .env(NSPTestEnv.TEST1_CNSP)
                .certAndKey(moces3CertAndKey)
                .cpr("0501792275")
                .role("role")
                .occupation("occupation")
                .authorizationCode("J0184")
                .systemName("systemname")
                .buildUserIdCard();

        userIdCard.sign();

        userIdCard.validate();

        String xml = XmlUtil.node2String(userIdCard.getAssertion(), false, false);

        IdCard idCard = new IdCardBuilder()
                .env(NSPTestEnv.TEST1_CNSP)
                .fromXml(xml)
                .buildIdCard();

        idCard.validate();

        assertEquals(UserIdCard.class, idCard.getClass());
    }

    @Test
    void canAutoDetectSystemIdCardType() throws Exception {

        IdCard systemIdCard = new IdCardBuilder()
                .env(NSPTestEnv.TEST1_CNSP)
                .certAndKey(new KeyStoreLoader().fromClassPath("FMKOnlineBilletOmv-T_OCES3.p12").password(KEYSTORE_PASSWORD.toCharArray()).load())
                .systemName("systemname")
                .buildSystemIdCard();

        systemIdCard.sign();

        systemIdCard.validate();

        String xml = XmlUtil.node2String(systemIdCard.getAssertion(), false, false);

        IdCard idCard = new IdCardBuilder()
                .env(NSPTestEnv.TEST1_CNSP)
                .fromXml(xml)
                .buildIdCard();

        idCard.validate();

        String cvr = idCard.getAttribute("medcom:CareProviderID");
        assertEquals("33257872", cvr);

        assertEquals(SystemIdCard.class, idCard.getClass());
    }

}
