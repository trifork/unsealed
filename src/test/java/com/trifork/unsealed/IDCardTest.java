package com.trifork.unsealed;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.time.LocalDateTime;

import org.junit.jupiter.api.Test;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

public class IDCardTest extends AbstractTest {
    private static final String KEYSTORE_PASSWORD = "Test1234";

    @Test
    void canSignIdCard() throws Exception {
        IdCardBuilder builder = new IdCardBuilder();
        IdCard idCard = builder.env(NSPTestEnv.TEST1_CNSP).keystoreFromClassPath("LarsLarsen.p12")
                .keystorePassword(KEYSTORE_PASSWORD.toCharArray()).cpr("0501792275").role("role")
                .occupation("occupation").authorizationCode("authid").systemName("systemname").buildUserIdCard();
        idCard.sign();
    }

    @Test
    void canSignSystemIdCard() throws Exception {
        IdCardBuilder builder = new IdCardBuilder();
        IdCard idCard = builder.env(NSPTestEnv.TEST1_CNSP).keystoreFromClassPath("TRIFORK AS - FMK-online.jks")
                .keystorePassword(KEYSTORE_PASSWORD.toCharArray()).systemName("systemname").buildSystemIdCard();
        idCard.sign();

        assertEquals("TEST1-NSP-STS", idCard.getIssuer());
        String subjectName = idCard.getSubjectName();
        assertNotNull(subjectName);

        Document doc = IdCard.getDocBuilder().newDocument();

        Element copy = idCard.serialize2DOMDocument(doc);
        doc.appendChild(copy);

        String serialized = XmlUtil.node2String(doc, true, false);

        assertTrue(serialized.contains("Assertion"));

        LocalDateTime notBefore = idCard.getNotBefore();
        assertTrue(notBefore.isBefore(LocalDateTime.now()));

        LocalDateTime notOnOrAfter = idCard.getNotOnOrAfter();
        assertTrue(notOnOrAfter.isAfter(LocalDateTime.now()));
    }

    @Test
    void canExchangeIdCardToOIOSAMLToken() throws Exception {
        IdCardBuilder builder = new IdCardBuilder();
        IdCard idCard = builder.env(NSPTestEnv.TEST1_DNSP).keystoreFromClassPath("LarsLarsen.p12")
                .keystorePassword(KEYSTORE_PASSWORD.toCharArray()).cpr("0501792275").role("role")
                .occupation("occupation").systemName("systemname").buildUserIdCard();
        idCard.sign();

        OIOSAMLToken samlToken = idCard.exchangeToOIOSAMLToken("https://saml.test1.fmk.netic.dk/fmk/");
        assertNotNull(samlToken);
    }
}
