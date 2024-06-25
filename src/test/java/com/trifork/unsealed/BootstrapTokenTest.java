package com.trifork.unsealed;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.time.LocalDateTime;
import java.time.ZonedDateTime;
import java.util.Base64;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

public class BootstrapTokenTest extends AbstractTest {

    private BootstrapTokenIssuer issuer;
    private CertAndKey spCertAndKey;
    private CertAndKey idpCertAndKey;
    private CertAndKey idpCertAndKeyForLegacyBootstrapTokens;

    @BeforeEach
    void setup0() throws Exception {
        spCertAndKey = new KeyStoreLoader().fromClassPath("NSP_Test_Service_Consumer_sds.p12")
                .password("Test1234").load();
        idpCertAndKey = new KeyStoreLoader().fromClassPath("NSP_Test_Identity_Provider_sds.p12")
                .password("Test1234").load();

        idpCertAndKeyForLegacyBootstrapTokens = new KeyStoreLoader()
                .fromClassPath("TEST whitelisted SP SOSI alias.p12")
                .password("Test1234").load();

        issuer = new BootstrapTokenIssuer()
                .env(NSPTestEnv.TEST1_CNSP)
                .idpCertAndKey(idpCertAndKey)
                .spCertAndKey(spCertAndKey);

        AbstractTest.setup();
    }

    @Test
    void canIssueBootstrapTokenForCitizen() throws Exception {
        BootstrapToken bootstrapToken = issuer.cpr("1102014746").issueForCitizen();

        assertNotNull(bootstrapToken);
    }

    @Test
    void canIssueBootstrapTokenForPro() throws Exception {
        BootstrapToken bootstrapToken = issuer.uuid("53767053-0628-4176-b66f-0da3a0b6e868").cvr("33257872")
                .orgName("Sundhedsdatastyrelsen").issueForProfessional();

        assertNotNull(bootstrapToken);
    }

    @Test
    void canExchangeLegacyBootstrapTokenToIDWSToken() throws Exception {

        String xml = BootstrapTokenHelper.createLegacyCitizenBootstrapToken(
                idpCertAndKeyForLegacyBootstrapTokens.certificate,
                idpCertAndKeyForLegacyBootstrapTokens.privateKey,
                "C=DK,O=Ingen organisatorisk tilknytning,CN=Lars Larsen,Serial=PID:9208-2002-2-514358910503");

        BootstrapToken bst = new BootstrapTokenBuilder().env(NSPTestEnv.TEST1_DNSP)
                .spCertAndKey(new KeyStoreLoader().fromClassPath("FMKOnlineBilletOmv-T_OCES3.p12")
                        .password("Test1234").load())
                .fromXml(xml).build();

        IdentityToken idwsToken = bst.exchangeToIdentityToken("https://fmk", "0501792275");

        assertNotNull(idwsToken.assertion);
        assertEquals("https://fmk", idwsToken.audience);
        assertTrue(idwsToken.created.isBefore(ZonedDateTime.now()));
        assertTrue(idwsToken.expires.isAfter(idwsToken.created.plusSeconds(5)));
    }

    @Test
    void canExchangeBootstrapTokenToIDWSToken() throws Exception {

        BootstrapToken bst = issuer.cpr("0501792275").issueForCitizen();

        IdentityToken idwsToken = bst.exchangeToIdentityToken("https://fmk", "0501792275");

        assertNotNull(idwsToken.assertion);
        assertEquals("https://fmk", idwsToken.audience);
        assertTrue(idwsToken.created.isBefore(ZonedDateTime.now()));
        assertTrue(idwsToken.expires.isAfter(idwsToken.created.plusSeconds(5)));
    }

    @Test
    void canExchangeBootstrapTokenToIDWSTokenWithProcuration() throws Exception {
        BootstrapToken bst = issuer.cpr("0501792275").issueForCitizen();

        IdentityToken idwsToken = bst.exchangeToIdentityToken("https://fmk", "0501792275", "1111111118");

        // Extract priviledge attribibute, base64 decode it, and verify that our procuration cpr is there
        Element attributeStatement = XmlUtil.getChild(idwsToken.assertion, NsPrefixes.saml,
                "AttributeStatement");
        String privsBase64 = SamlUtil.getSamlAttribute(attributeStatement,
                "dk:gov:saml:attribute:Privileges_intermediate");
        String privs = new String(Base64.getDecoder().decode(privsBase64), StandardCharsets.UTF_8);

        Document doc = XmlUtil.getDocBuilder()
                .parse(new ByteArrayInputStream(privs.getBytes(StandardCharsets.UTF_8)));

        XPathContext xpath = new XPathContext(doc);
        Element privileges = xpath.findElement(doc.getDocumentElement(),
                "/" + NsPrefixes.bpp.name() + ":PrivilegeList/"
                        + NsPrefixes.bpp.name() + ":PrivilegeGroup");

        assertEquals("urn:dk:healthcare:saml:actThroughProcurationBy:cprNumberIdentifier:1111111118",
                privileges.getAttribute("Scope"));
    }

    @Test
    void cannotExchangeExpiredBootstrapTokenToIDWSToken() throws Exception {

        String xml = readFromClasspath("/bootstrap-token.xml");

        BootstrapToken bst = new BootstrapTokenBuilder().env(NSPTestEnv.TEST1_DNSP)
                .spCertAndKey(new KeyStoreLoader().fromClassPath("FMKOnlineBilletOmv-T_OCES3.p12")
                        .password("Test1234").load())
                .fromXml(xml).build();

        assertThrows(STSInvocationException.class, () -> {
            bst.exchangeToIdentityToken("https://fmk", "0501792275");
        });

    }

    @Test
    void canExchangeJWTTokenToIDWSToken() throws Exception {

        String jwt = OIDC.authenticate("0501792275");

        BootstrapToken bst = new BootstrapTokenBuilder().env(NSPTestEnv.TEST1_DNSP)
                .spCertAndKey(new KeyStoreLoader().fromClassPath("FMKOnlineBilletOmv-T_OCES3.p12")
                        .password("Test1234").load())
                .fromJwt(jwt).build();

        IdentityToken idwsToken = bst.exchangeToIdentityToken("https://fmk", "0501792275");
        assertNotNull(idwsToken.assertion);
        assertEquals("https://fmk", idwsToken.audience);
        assertTrue(idwsToken.created.isBefore(ZonedDateTime.now()));
        assertTrue(idwsToken.expires.isAfter(idwsToken.created.plusSeconds(5)));

    }

    @Test
    void cannotExchangeExpiredJWTTokenToIDWSToken() throws Exception {

        String jwt = "eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICIySWh5aEM4Y1o3WEtmVm1BVG53Wnpxam00THFwMWFnN000d3UyTjNLVGtzIn0.eyJleHAiOjE2OTkwMjU1NjgsIm5iZiI6MCwiaWF0IjoxNjk5MDIxOTY4LCJhdXRoX3RpbWUiOjE2OTkwMjE5NjgsImp0aSI6IjAzYzE5OGY2LWFjNTktNDU2NS1hODczLWQzMmM2NDdkYjA2MiIsImlzcyI6Imh0dHBzOi8vb2lkYy10ZXN0Lmhvc3RlZC50cmlmb3JrLmNvbS9hdXRoL3JlYWxtcy9zZHMiLCJhdWQiOiJmbWtfbW9jayIsInN1YiI6IjRlZGI5MjgwLTIxMjQtNGNiNi04NDcwLWViMzhhNjFmM2Y3MCIsInR5cCI6IkJlYXJlciIsImF6cCI6ImZta19tb2NrIiwibm9uY2UiOiIzMzQxMTI5Iiwic2Vzc2lvbl9zdGF0ZSI6IjM1YWMwMzhkLTZlMmQtNDA2Ny1iM2RjLTJjMWM0MTkyYzg2NSIsImFjciI6IjEiLCJzY29wZSI6Im9wZW5pZCBmbWsgb2ZmbGluZV9hY2Nlc3Mgc29zaS1zdHMgcHJvZmlsZSBldmVudGJveCIsInNpZCI6IjM1YWMwMzhkLTZlMmQtNDA2Ny1iM2RjLTJjMWM0MTkyYzg2NSIsImNwciI6IjA1MDE3OTIyNzUiLCJjZXJ0bmFtZSI6Ik1va2V5IE1pY2siLCJjZXJ0c3ViZG4iOiJDTj1Nb2tleSBNaWNrK3NlcmlhbG51bWJlcj1QSUQ6cGlkMDUwMTc5MjI3NSxPPUluZ2VuIG9yZ2FuaXNhdG9yaXNrIHRpbGtueXRuaW5nLEM9REsiLCJuYW1lIjoiTW9rZXkgTWljayIsInByZWZlcnJlZF91c2VybmFtZSI6InBpZC0wNTAxNzkyMjc1IiwiZ2l2ZW5fbmFtZSI6Ik1va2V5IiwiZmFtaWx5X25hbWUiOiJNaWNrIn0.UgbcaY6mdXZihgdQVD_fumypnuyY6gZWJyXuqMGOz3DddhjpaYk_xsyka6dOK5Xn3pQ1B_OcSkR6YkFK4Zdy2uWXa7H1_H-fVS-Wb8OYfvq-FrUpGE4N9F-3pWwyy48Qw5wdE9Z11KTgethShWRHcbyOhSfKqqwJXQg4MKNfzpkeZM0bU76jm7JeMreIqVhOM78lvCl_VGGcsZb-iXj3kTPn-A1QbmsTmtrI0uIZaPdmatojcKoJNnMgTyYUgxDHw8eaA0fFMEQgqInU9voLPQm23MZHJi55JRKCdUJY0-w4pOMOrhKcx95iTsyjDuYcd0aRNv_LBcT_RquNun3KKpezS5E-MgTZPyEVz-gVo7aFHWY7-BjXTOeEcdenu_lhisFqCymxN0FJabJ7otj0yWPjpAgcLeIg3W_G5ebt6Luhh0ezIZtAPfjqpInHDsqAGQnDwKInj0t6xKb5p-ZRHZhbIok_TosA83Xkr6KeqMQ8EBsf6Bek2eUrxZz2Cb52";

        BootstrapToken bst = new BootstrapTokenBuilder().env(NSPTestEnv.TEST1_DNSP)
                .spCertAndKey(new KeyStoreLoader().fromClassPath("FMKOnlineBilletOmv-T_OCES3.p12")
                        .password("Test1234").load())
                .fromJwt(jwt).build();

        STSInvocationException e = assertThrows(STSInvocationException.class, () -> {
            bst.exchangeToIdentityToken("https://fmk", "0501792275");
        });

        assertTrue(e.getMessage().contains("expired"));
    }

    @Test
    void canExchangeBootstrapTokenToIdCard() throws Exception {
        BootstrapToken bst = issuer.uuid("92336cc1-b3a4-4742-be54-c723bfa99aba").cvr("20921897")
                .orgName("Trifork").issueForProfessional();

        UserIdCard userIdCard = bst.exchangeToUserIdCard("https://fmk", null, null, "J0184", "FMK-online");

        assertTrue(userIdCard.getNotBefore().isBefore(LocalDateTime.now()));
        assertTrue(userIdCard.getNotOnOrAfter().isAfter(LocalDateTime.now()));
        assertEquals("Lars", userIdCard.getAttribute("medcom:UserGivenName"));
    }

    @Test
    void canExchangeBootstrapTokenViaXmlToIdCard() throws Exception {
        BootstrapToken bst = issuer.uuid("53767053-0628-4176-b66f-0da3a0b6e868").cvr("33257872")
                .orgName("Sundhedsdatastyrelsen").issueForProfessional();

        var xml = bst.getXml();

        ZonedDateTime notOnOrAfter = bst.getNotOnOrAfter();

        assertTrue(notOnOrAfter.isAfter(ZonedDateTime.now()));

        // Initialize a new BootstrapToken from xml string:
        BootstrapToken bst2 = new BootstrapTokenBuilder().env(NSPTestEnv.TEST1_CNSP).spCertAndKey(spCertAndKey)
                .fromXml(xml).build();

        UserIdCard userIdCard = bst2.exchangeToUserIdCard("https://fmk", null, null, "MJP84", "FMK-online");

        assertTrue(userIdCard.getNotBefore().isBefore(LocalDateTime.now()));
        assertTrue(userIdCard.getNotOnOrAfter().isAfter(LocalDateTime.now()));
    }

    private String readFromClasspath(String path) throws IOException {
        InputStream is = this.getClass().getResourceAsStream(path);
        ByteArrayOutputStream os = new ByteArrayOutputStream();
        int nRead;
        byte[] data = new byte[1024];
        while ((nRead = is.read(data, 0, data.length)) != -1) {
            os.write(data, 0, nRead);
        }

        return os.toString(StandardCharsets.UTF_8.name());
    }

}