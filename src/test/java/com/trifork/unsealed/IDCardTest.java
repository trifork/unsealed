package com.trifork.unsealed;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.time.LocalDateTime;

import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

public class IDCardTest extends AbstractTest {
    private static final String KEYSTORE_PASSWORD = "Test1234";

    @Disabled
    @Test
    void canSignMoces2IdCard() throws Exception {

        IdCard idCard = new IdCardBuilder().env(NSPTestEnv.TEST1_CNSP)
                .certAndKey(new KeyStoreLoader().fromClassPath("TRIFORK AS - Lars Larsen.p12").password(KEYSTORE_PASSWORD.toCharArray()).load())
                .cpr("0501792275").role("role")
                .occupation("occupation").authorizationCode("authid").systemName("systemname").buildUserIdCard();

        idCard.sign();

        idCard.validate();
    }

    @Test
    void canSignIdCard() throws Exception {

        IdCard idCard = new IdCardBuilder().env(NSPTestEnv.TEST1_CNSP)
                .certAndKey(new KeyStoreLoader().fromClassPath("Lars_Larsen_prodben.p12").password(KEYSTORE_PASSWORD.toCharArray()).load())
                .cpr("0501792275").role("role")
                .occupation("occupation").authorizationCode("J0184").systemName("systemname").buildUserIdCard();

        idCard.sign();

        idCard.validate();
    }

    @Test
    void canSignMoces2SystemIdCard() throws Exception {

        IdCard idCard = new IdCardBuilder().env(NSPTestEnv.TEST1_CNSP)
                .certAndKey(new KeyStoreLoader().fromClassPath("FMKOnlineBilletOmv-T_OCES3.p12").password(KEYSTORE_PASSWORD.toCharArray()).load())
                .systemName("systemname").buildSystemIdCard();

        idCard.sign();

        assertEquals("TEST1-NSP-STS", idCard.getIssuer());
        String subjectName = idCard.getSubjectName();
        assertNotNull(subjectName);

        Document doc = XmlUtil.getDocBuilder().newDocument();

        Element copy = idCard.serialize2DOMDocument(doc);
        doc.appendChild(copy);

        String serialized = XmlUtil.node2String(doc, true, false);

        assertTrue(serialized.contains("Assertion"));

        LocalDateTime notBefore = idCard.getNotBefore();
        assertTrue(notBefore.isBefore(LocalDateTime.now()));

        LocalDateTime notOnOrAfter = idCard.getNotOnOrAfter();
        assertTrue(notOnOrAfter.isAfter(LocalDateTime.now()));

        idCard.validate();
    }

    @Test
    void canSignSystemIdCard() throws Exception {

        IdCard idCard = new IdCardBuilder().env(NSPTestEnv.TEST1_CNSP)
                .certAndKey(new KeyStoreLoader().fromClassPath("FMKOnlineBilletOmv-T_OCES3.p12").password(KEYSTORE_PASSWORD.toCharArray()).load())
                .systemName("systemname").buildSystemIdCard();

        idCard.sign();

        assertEquals("TEST1-NSP-STS", idCard.getIssuer());
        String subjectName = idCard.getSubjectName();
        assertNotNull(subjectName);

        Document doc = XmlUtil.getDocBuilder().newDocument();

        Element copy = idCard.serialize2DOMDocument(doc);
        doc.appendChild(copy);

        String serialized = XmlUtil.node2String(doc, true, false);

        assertTrue(serialized.contains("Assertion"));

        LocalDateTime notBefore = idCard.getNotBefore();
        assertTrue(notBefore.isBefore(LocalDateTime.now()));

        LocalDateTime notOnOrAfter = idCard.getNotOnOrAfter();
        assertTrue(notOnOrAfter.isAfter(LocalDateTime.now()));

        idCard.validate();
    }

    @Disabled
    @Test
    void canExchangeMoces2IdCardToOIOSAMLToken() throws Exception {

        IdCard idCard = new IdCardBuilder().env(NSPTestEnv.TEST1_CNSP)
                .certAndKey(new KeyStoreLoader().fromClassPath("TRIFORK AS - Lars Larsen.p12").password(KEYSTORE_PASSWORD.toCharArray()).load())
                .cpr("0501792275").role("role")
                .occupation("occupation").systemName("systemname").buildUserIdCard();

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

        IdCard idCard = new IdCardBuilder().env(NSPTestEnv.TEST1_CNSP)
                .certAndKey(new KeyStoreLoader().fromClassPath("Lars_Larsen_prodben.p12").password(KEYSTORE_PASSWORD.toCharArray()).load())
                .cpr("0501792275").role("role")
                .occupation("occupation").systemName("systemname").buildUserIdCard();

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

        IdCard idCard = new IdCardBuilder().env(NSPTestEnv.TEST1_CNSP)
                .certAndKey(new KeyStoreLoader().fromClassPath("Lars_Larsen_prodben.p12").password(KEYSTORE_PASSWORD.toCharArray()).load())
                .cpr("0501792275").role("role")
                .occupation("occupation").authorizationCode("J0184").systemName("systemname").buildUserIdCard();

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

}
