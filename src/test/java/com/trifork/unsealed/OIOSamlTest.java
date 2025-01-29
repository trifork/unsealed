package com.trifork.unsealed;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.time.ZonedDateTime;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;

public class OIOSamlTest extends AbstractTest {
    private static final String KEYSTORE_PASSWORD = "Test1234";
    private OIOSAMLTokenIssuer samlTokenIssuer;
    private BootstrapTokenIssuer bootstrapTokenIssuer;

    @BeforeEach
    void setup0() throws Exception {
        AbstractTest.setup();

        CertAndKey spCertAndKey = new KeyStoreLoader().fromClassPath("FMKOnlineBilletOmv-T_OCES3.p12").password(KEYSTORE_PASSWORD).load();
        CertAndKey idpCertAndKey = new KeyStoreLoader().fromClassPath("TEST whitelisted SP SOSI alias.p12").password(KEYSTORE_PASSWORD).load();

        bootstrapTokenIssuer = new BootstrapTokenIssuer()
                .idpCertAndKey(idpCertAndKey);

        // Note that bootstrapTokenIssuer could be using a different CertAndKey than samlTokenIssuer
        samlTokenIssuer = new OIOSAMLTokenIssuer()
                .idpCertAndKey(idpCertAndKey)
                .spCert(spCertAndKey.certificate)
                .bootstrapTokenIssuer(bootstrapTokenIssuer);

    }

    @Test
    void canIssueOIOSAMLTokenForProfessional() throws Exception {
        OIOSAMLToken token = issueSamlTokenForProf();
        assertEquals("Lars Larsen", token.getCommonName());
        assertEquals("3", token.getAssuranceLevel());
        assertEquals("https://fmk", token.getAudienceRestriction());
        assertEquals("0501792275", token.getCpr());
        assertEquals("5f2d86da-ed21-4593-a324-fa892e552ac1", token.getCprUuid());
        assertEquals("92336cc1-b3a4-4742-be54-c723bfa99aba", token.getProfUuid());
        assertEquals("20921897", token.getCvrNumberIdentifier());
        assertEquals("fmk-support@trifork.com", token.getEmail());
        assertTrue(ZonedDateTime.now().isAfter(token.getNotBefore()));
        assertTrue(ZonedDateTime.now().isBefore(token.getNotOnOrAfter()));
        assertEquals("TRIFORK A/S", token.getOrganizationName());
        assertEquals("OIOSAML-H-3.0", token.getSpecVersion());
        assertEquals("Larsen", token.getSurName());
        assertTrue(ZonedDateTime.now().isAfter(token.getUserAuthenticationInstant()));
    }

    @Test
    void canIssueOIOSAMLTokenForCitizen() throws Exception {
        OIOSAMLToken token = issueSamlTokenForCitizen();
        assertEquals("Lars Larsen", token.getCommonName());
        assertEquals("3", token.getAssuranceLevel());
        assertEquals("https://fmk", token.getAudienceRestriction());
        assertEquals("0501792275", token.getCpr());
        assertEquals("5f2d86da-ed21-4593-a324-fa892e552ac1", token.getCprUuid());
        assertTrue(ZonedDateTime.now().isAfter(token.getNotBefore()));
        assertTrue(ZonedDateTime.now().isBefore(token.getNotOnOrAfter()));
        assertEquals("OIOSAML-H-3.0", token.getSpecVersion());
        assertEquals("Larsen", token.getSurName());
        assertTrue(ZonedDateTime.now().isAfter(token.getUserAuthenticationInstant()));
    }

    @Disabled
    @Test
    void canExchangeOIOSAMLTokenToIdCard() throws Exception {
        OIOSAMLToken token = issueSamlTokenForProf();

        String assertion = XmlUtil.node2String(token.getAssertion(), false, false);

        OIOSAMLTokenBuilder samlTokenBuilder = new OIOSAMLTokenBuilder();
        OIOSAMLToken samlToken = samlTokenBuilder.env(NSPTestEnv.TEST1_DNSP)
                .spCertAndKey(new KeyStoreLoader().fromClassPath("FMKOnlineBilletOmv-T_OCES3.p12").password(KEYSTORE_PASSWORD.toCharArray()).load())
                .fromXml(assertion).build();

        IdCard exchangedIdCard = samlToken.exchangeToIdCard("FMK-online", "J0184", "doctor");
        assertNotNull(exchangedIdCard);

        String subjectName = exchangedIdCard.getSubjectName();
        assertEquals("0501792275", subjectName);

        String asString = exchangedIdCard.getXml(false, false);
        assertTrue(asString.contains("Larsen"));
    }

    private OIOSAMLToken issueSamlTokenForProf() throws Exception {

        OIOSAMLToken token = samlTokenIssuer
                .audience("https://fmk")
                .commonName("Lars Larsen")
                .cprNumber("0501792275")
                .cvrNumber("20921897")
                .cprUuid("5f2d86da-ed21-4593-a324-fa892e552ac1")
                .profUuid("92336cc1-b3a4-4742-be54-c723bfa99aba")
                .email("fmk-support@trifork.com")
                .issuer("https://saml.nemlog-in.dk")
                .organisationName("TRIFORK A/S")
                .recipient("https://test1.fmk.netic.dk/fmk/saml/SAMLAssertionConsumer")
                .ridNumber("52723247")
                .surName("Larsen")
                .uid("CVR:20921897-RID:52723247")
                .issueForProfessional();
        return token;
    }

    private OIOSAMLToken issueSamlTokenForCitizen() throws Exception {

        OIOSAMLToken token = samlTokenIssuer
                .audience("https://fmk")
                .commonName("Lars Larsen")
                .cprNumber("0501792275")
                .cprUuid("5f2d86da-ed21-4593-a324-fa892e552ac1")
                .issuer("https://saml.nemlog-in.dk")
                .recipient("https://test1.fmk.netic.dk/fmk/saml/SAMLAssertionConsumer")
                .surName("Larsen")
                .issueForCitizen();
        return token;
    }
}
