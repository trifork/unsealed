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
import java.security.Key;
import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.time.LocalDateTime;
import java.time.ZonedDateTime;
import java.util.Base64;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

public class BootstrapTokenTest extends AbstractTest {

    private static X509Certificate idpCert;
    private static X509Certificate idpCert2;
    private static X509Certificate spCert;
    private static X509Certificate spCert2;
    private static Key idpPrivateKey;
    private static Key idpPrivateKey2;

    @BeforeEach
    void setup0() throws Exception {
        KeyStore idpKeyStore = KeyStore.getInstance("PKCS12");
        idpKeyStore.load(BootstrapTokenHelper.class.getResourceAsStream("/TEST whitelisted SP SOSI alias.p12"),
                "Test1234".toCharArray());

        KeyStore spKeyStore = KeyStore.getInstance("PKCS12");
        spKeyStore.load(BootstrapTokenHelper.class.getResourceAsStream("/FMKOnlineBilletOmv-T_OCES3.p12"),
                "Test1234".toCharArray());

        KeyStore idpKeyStore2 = KeyStore.getInstance("PKCS12");
        idpKeyStore2.load(BootstrapTokenHelper.class.getResourceAsStream("/NSP_Test_Identity_Provider_sds.p12"),
                "Test1234".toCharArray());

        KeyStore spKeyStore2 = KeyStore.getInstance("PKCS12");
        spKeyStore2.load(BootstrapTokenHelper.class.getResourceAsStream("/NSP_Test_Service_Consumer_sds.p12"),
                "Test1234".toCharArray());

        AbstractTest.setup();

        idpCert = (X509Certificate) idpKeyStore.getCertificate(idpKeyStore.aliases().nextElement());
        idpPrivateKey = idpKeyStore.getKey(idpKeyStore.aliases().nextElement(), "Test1234".toCharArray());

        spCert = (X509Certificate) spKeyStore.getCertificate(spKeyStore.aliases().nextElement());
        spCert2 = (X509Certificate) spKeyStore2.getCertificate(spKeyStore2.aliases().nextElement());

        idpCert2 = (X509Certificate) idpKeyStore2.getCertificate(idpKeyStore2.aliases().nextElement());
        idpPrivateKey2 = idpKeyStore2.getKey(idpKeyStore2.aliases().nextElement(), "Test1234".toCharArray());
    }

    @Test
    void canExchangeLegacyBootstrapTokenToIDWSToken() throws Exception {

        String xml = BootstrapTokenHelper.createLegacyCitizenBootstrapToken(idpCert,
                idpPrivateKey,
                "C=DK,O=Ingen organisatorisk tilknytning,CN=Lars Larsen,Serial=PID:9208-2002-2-514358910503");

        BootstrapToken bst = new BootstrapTokenBuilder().env(NSPTestEnv.TEST1_DNSP)
                .keystoreFromClassPath("FMKOnlineBilletOmv-T_OCES3.p12")
                .keystorePassword("Test1234".toCharArray())
                .fromXml(xml).build();

        IdentityToken idwsToken = bst.exchangeToIdentityToken("https://fmk", "0501792275");

        assertNotNull(idwsToken.assertion);
        assertEquals("https://fmk", idwsToken.audience);
        assertTrue(idwsToken.created.isBefore(ZonedDateTime.now()));
        assertTrue(idwsToken.expires.isAfter(idwsToken.created.plusSeconds(5)));
    }

    @Test
    void canExchangeBootstrapTokenToIDWSToken() throws Exception {

        String xml = BootstrapTokenHelper.createCitizenBootstrapToken(idpCert2, idpPrivateKey2, spCert,
                "0501792275");

        BootstrapToken bst = new BootstrapTokenBuilder().env(NSPTestEnv.TEST1_DNSP)
                .keystoreFromClassPath("FMKOnlineBilletOmv-T_OCES3.p12")
                .keystorePassword("Test1234".toCharArray())
                .fromXml(xml).build();

        IdentityToken idwsToken = bst.exchangeToIdentityToken("https://fmk", "0501792275");

        assertNotNull(idwsToken.assertion);
        assertEquals("https://fmk", idwsToken.audience);
        assertTrue(idwsToken.created.isBefore(ZonedDateTime.now()));
        assertTrue(idwsToken.expires.isAfter(idwsToken.created.plusSeconds(5)));
    }

    @Test
    void cannotBuildBootstrapTokenWithWrongAlias() throws Exception {

        String xml = BootstrapTokenHelper.createLegacyCitizenBootstrapToken(idpCert, idpPrivateKey,
                "C=DK,O=Ingen organisatorisk tilknytning,CN=Lars Larsen,Serial=PID:9208-2002-2-514358910503");

        assertThrows(IllegalArgumentException.class,
                () -> new BootstrapTokenBuilder().env(NSPTestEnv.TEST1_DNSP)
                        .keystoreFromClassPath("FMKOnlineBilletOmv-T_OCES3.p12")
                        .keystorePassword("Test1234".toCharArray())
                        .keystoreAlias("wrongalias").fromXml(xml).build());

    }

    @Test
    void canExchangeBootstrapTokenToIDWSTokenWithProcuration() throws Exception {

        String xml = BootstrapTokenHelper.createLegacyCitizenBootstrapToken(idpCert, idpPrivateKey,
                "C=DK,O=Ingen organisatorisk tilknytning,CN=Lars Larsen,Serial=PID:9208-2002-2-514358910503");

        BootstrapToken bst = new BootstrapTokenBuilder().env(NSPTestEnv.TEST1_DNSP)
                .keystoreFromClassPath("FMKOnlineBilletOmv-T_OCES3.p12")
                .keystorePassword("Test1234".toCharArray())
                .fromXml(xml).build();

        IdentityToken idwsToken = bst.exchangeToIdentityToken("https://fmk", "0501792275", "1111111118");

        // Extract priviledge attribibute, base64 decode it, and verify that our
        // procuration cpr is there
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
    void cannotExchangeObsoleteBootstrapTokenToIDWSToken() throws Exception {

        String xml = readFromClasspath("/bootstrap-token.xml");

        BootstrapToken bst = new BootstrapTokenBuilder().env(NSPTestEnv.TEST1_DNSP)
                .keystoreFromClassPath("FMKOnlineBilletOmv-T_OCES3.p12")
                .keystorePassword("Test1234".toCharArray())
                .fromXml(xml).build();

        assertThrows(STSInvocationException.class, () -> {
            bst.exchangeToIdentityToken("https://fmk", "0501792275");
        });

    }

    @Test
    void cannotExchangeObsoleteJWTTokenToIDWSToken() throws Exception {

        String jwt = "eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICIySWh5aEM4Y1o3WEtmVm1BVG53Wnpxam00THFwMWFnN000d3UyTjNLVGtzIn0.eyJleHAiOjE2OTkwMjU1NjgsIm5iZiI6MCwiaWF0IjoxNjk5MDIxOTY4LCJhdXRoX3RpbWUiOjE2OTkwMjE5NjgsImp0aSI6IjAzYzE5OGY2LWFjNTktNDU2NS1hODczLWQzMmM2NDdkYjA2MiIsImlzcyI6Imh0dHBzOi8vb2lkYy10ZXN0Lmhvc3RlZC50cmlmb3JrLmNvbS9hdXRoL3JlYWxtcy9zZHMiLCJhdWQiOiJmbWtfbW9jayIsInN1YiI6IjRlZGI5MjgwLTIxMjQtNGNiNi04NDcwLWViMzhhNjFmM2Y3MCIsInR5cCI6IkJlYXJlciIsImF6cCI6ImZta19tb2NrIiwibm9uY2UiOiIzMzQxMTI5Iiwic2Vzc2lvbl9zdGF0ZSI6IjM1YWMwMzhkLTZlMmQtNDA2Ny1iM2RjLTJjMWM0MTkyYzg2NSIsImFjciI6IjEiLCJzY29wZSI6Im9wZW5pZCBmbWsgb2ZmbGluZV9hY2Nlc3Mgc29zaS1zdHMgcHJvZmlsZSBldmVudGJveCIsInNpZCI6IjM1YWMwMzhkLTZlMmQtNDA2Ny1iM2RjLTJjMWM0MTkyYzg2NSIsImNwciI6IjA1MDE3OTIyNzUiLCJjZXJ0bmFtZSI6Ik1va2V5IE1pY2siLCJjZXJ0c3ViZG4iOiJDTj1Nb2tleSBNaWNrK3NlcmlhbG51bWJlcj1QSUQ6cGlkMDUwMTc5MjI3NSxPPUluZ2VuIG9yZ2FuaXNhdG9yaXNrIHRpbGtueXRuaW5nLEM9REsiLCJuYW1lIjoiTW9rZXkgTWljayIsInByZWZlcnJlZF91c2VybmFtZSI6InBpZC0wNTAxNzkyMjc1IiwiZ2l2ZW5fbmFtZSI6Ik1va2V5IiwiZmFtaWx5X25hbWUiOiJNaWNrIn0.UgbcaY6mdXZihgdQVD_fumypnuyY6gZWJyXuqMGOz3DddhjpaYk_xsyka6dOK5Xn3pQ1B_OcSkR6YkFK4Zdy2uWXa7H1_H-fVS-Wb8OYfvq-FrUpGE4N9F-3pWwyy48Qw5wdE9Z11KTgethShWRHcbyOhSfKqqwJXQg4MKNfzpkeZM0bU76jm7JeMreIqVhOM78lvCl_VGGcsZb-iXj3kTPn-A1QbmsTmtrI0uIZaPdmatojcKoJNnMgTyYUgxDHw8eaA0fFMEQgqInU9voLPQm23MZHJi55JRKCdUJY0-w4pOMOrhKcx95iTsyjDuYcd0aRNv_LBcT_RquNun3KKpezS5E-MgTZPyEVz-gVo7aFHWY7-BjXTOeEcdenu_lhisFqCymxN0FJabJ7otj0yWPjpAgcLeIg3W_G5ebt6Luhh0ezIZtAPfjqpInHDsqAGQnDwKInj0t6xKb5p-ZRHZhbIok_TosA83Xkr6KeqMQ8EBsf6Bek2eUrxZz2Cb52";

        BootstrapToken bst = new BootstrapTokenBuilder().env(NSPTestEnv.TEST1_DNSP)
                .keystoreFromClassPath("FMKOnlineBilletOmv-T_OCES3.p12")
                .keystorePassword("Test1234".toCharArray())
                .fromJwt(jwt).build();

        STSInvocationException e = assertThrows(STSInvocationException.class, () -> {
            bst.exchangeToIdentityToken("https://fmk", "0501792275");
        });

        assertTrue(e.getMessage().contains("expired"));
    }

    @Test
    void canExchangeBootstrapTokenToIdCard() throws Exception {

        String xml = BootstrapTokenHelper.createProfessionalBootstrapToken(idpCert2, idpPrivateKey2, spCert2, "53767053-0628-4176-b66f-0da3a0b6e868", "33257872", "Sundhedsdatastyrelsen");

        BootstrapToken bst = new BootstrapTokenBuilder().env(NSPTestEnv.TEST1_DNSP)
                .keystoreFromClassPath("NSP_Test_Service_Consumer_sds.p12")
                .keystorePassword("Test1234".toCharArray())
                .fromXml(xml).build();

        // UserIdCard userIdCard = bst.exchangeToUserIdCard("https://fmk", "ef6e6b1a-3373-4a30-b8ec-cbf16ef69a3e", null, null, "MJP84", "FMK-online");
        UserIdCard userIdCard = bst.exchangeToUserIdCard("https://fmk", null, null, "MJP84", "FMK-online");

        assertTrue(userIdCard.getNotBefore().isBefore(LocalDateTime.now()));
        assertTrue(userIdCard.getNotOnOrAfter().isAfter(LocalDateTime.now()));

        // assertNotNull(userIdCard.assertion);
        // assertEquals("https://fmk", userIdCard.audience);
        // assertTrue(userIdCard.created.isBefore(ZonedDateTime.now()));
        // assertTrue(userIdCard.expires.isAfter(userIdCard.created.plusSeconds(5)));
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