package com.trifork.unsealed;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.time.ZonedDateTime;

import javax.xml.crypto.MarshalException;
import javax.xml.crypto.dsig.XMLSignatureException;
import javax.xml.parsers.ParserConfigurationException;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

public class OIOSamlTest extends AbstractTest {
    private static final String KEYSTORE_PASSWORD = "Test1234";
    private OIOSAMLTokenIssuer samlTokenIssuer;

    @BeforeEach
    void setup0() throws Exception {
        AbstractTest.setup();

        samlTokenIssuer = new OIOSAMLTokenIssuer().keystoreFromClassPath("TestTrustedIdpForBootstrapToken.p12")
                .keystorePassword("Test1234".toCharArray());

    }

    @Test
    void canIssueOIOSAMLToken() throws Exception {
        OIOSAMLToken token = issueSamlToken();
        assertEquals("Lars Larsen", token.getCommonName());
        assertEquals("3", token.getAssuranceLevel());
        assertEquals("https://fmk", token.getAudienceRestriction());
        assertEquals("0501792275", token.getCpr());
        assertEquals("20921897", token.getCvrNumberIdentifier());
        assertEquals("fmk-support@trifork.com", token.getEmail());
        assertTrue(ZonedDateTime.now().isAfter(token.getNotBefore()));
        assertTrue(ZonedDateTime.now().isBefore(token.getNotOnOrAfter()));
        assertEquals("TRIFORK A/S", token.getOrganizationName());
        assertEquals("DK-SAML-2.0", token.getSpecVersion());
        assertEquals("Larsen", token.getSurName());
        assertTrue(ZonedDateTime.now().isAfter(token.getUserAuthenticationInstant()));
    }

    @Test
    void canExchangeOIOSAMLTokenToIdCard() throws Exception {
        OIOSAMLToken token = issueSamlToken();

        String assertion = XmlUtil.node2String(token.getAssertion(), false, false);

        OIOSAMLTokenBuilder samlTokenBuilder = new OIOSAMLTokenBuilder();
        OIOSAMLToken samlToken = samlTokenBuilder.env(NSPTestEnv.TEST1_DNSP)
                .keystoreFromClassPath("FMKOnlineOiosamlSP-test1.jks")
                .keystorePassword(KEYSTORE_PASSWORD.toCharArray()).xml(assertion).build();

        IdCard exchangedIdCard = samlToken.exchangeToIdCard("FMK-online", "J0184", "doctor");
        assertNotNull(exchangedIdCard);

        String subjectName = exchangedIdCard.getSubjectName();
        assertEquals("0501792275", subjectName);

        String asString = exchangedIdCard.asString(false, false);
        assertTrue(asString.contains("Larsen"));
    }

    private OIOSAMLToken issueSamlToken() throws KeyStoreException, NoSuchAlgorithmException, CertificateException,
            IOException, UnrecoverableKeyException, InvalidAlgorithmParameterException, MarshalException,
            XMLSignatureException, ParserConfigurationException {
                
        OIOSAMLToken token = samlTokenIssuer
                .audience("https://fmk")
                .commonName("Lars Larsen")
                .cprNumber("0501792275")
                .cvrNumber("20921897")
                .email("fmk-support@trifork.com")
                .issuer("https://saml.nemlog-in.dk")
                .organisationName("TRIFORK A/S")
                .recipient("https://test1.fmk.netic.dk/fmk/saml/SAMLAssertionConsumer")
                .ridNumber("52723247")
                .subjectName("C=DK,O=TRIFORK A/S // CVR:20921897,CN=Lars Larsen,Serial=CVR:20921897-RID:52723247")
                .surName("Larsen")
                .uid("CVR:20921897-RID:52723247")
                .build();
        return token;
    }

}
