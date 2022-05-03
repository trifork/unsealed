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
import java.time.ZonedDateTime;
import java.util.Base64;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

public class BootstrapTokenTest extends AbstractTest {

    private static X509Certificate idpCert;
    private static Key idpPrivateKey;

    @BeforeEach
    void setup0() throws Exception {
        KeyStore idpKeyStore = KeyStore.getInstance("PKCS12");
        idpKeyStore.load(BootstrapTokenHelper.class.getResourceAsStream("/TestTrustedIdpForBootstrapToken.p12"),
                "Test1234".toCharArray());

        AbstractTest.setup();

        idpCert = (X509Certificate) idpKeyStore.getCertificate(idpKeyStore.aliases().nextElement());
        idpPrivateKey = idpKeyStore.getKey(idpKeyStore.aliases().nextElement(), "Test1234".toCharArray());
    }

    @Test
    void canExchangeBootstrapTokenToIDWSToken() throws Exception {

        String xml = BootstrapTokenHelper.createBootstrapToken(idpCert, idpPrivateKey,
                "C=DK,O=Ingen organisatorisk tilknytning,CN=Lars Larsen,Serial=PID:9208-2002-2-514358910503");

        BootstrapToken bst = new BootstrapTokenBuilder().env(NSPTestEnv.TEST1_DNSP)
                .keystoreFromClassPath("FMKOnlineBilletOmv-T.jks").keystorePassword("Test1234".toCharArray())
                .fromXml(xml).build();

        IdentityToken idwsToken = bst.exchangeToIdentityToken("https://fmk", "0501792275");

        assertNotNull(idwsToken.assertion);
        assertEquals("https://fmk", idwsToken.audience);
        assertTrue(idwsToken.created.isBefore(ZonedDateTime.now()));
        assertTrue(idwsToken.expires.isAfter(idwsToken.created.plusSeconds(5)));
    }

    @Test
    void cannotBuildBootstrapTokenWithWrongAlias() throws Exception {

        String xml = BootstrapTokenHelper.createBootstrapToken(idpCert, idpPrivateKey,
                "C=DK,O=Ingen organisatorisk tilknytning,CN=Lars Larsen,Serial=PID:9208-2002-2-514358910503");

        assertThrows(IllegalArgumentException.class, () -> new BootstrapTokenBuilder().env(NSPTestEnv.TEST1_DNSP)
                .keystoreFromClassPath("FMKOnlineBilletOmv-T.jks").keystorePassword("Test1234".toCharArray())
                .keystoreAlias("wrongalias").fromXml(xml).build());

    }

    @Test
    void canExchangeBootstrapTokenToIDWSTokenWithProcuration() throws Exception {

        String xml = BootstrapTokenHelper.createBootstrapToken(idpCert, idpPrivateKey,
                "C=DK,O=Ingen organisatorisk tilknytning,CN=Lars Larsen,Serial=PID:9208-2002-2-514358910503");

        BootstrapToken bst = new BootstrapTokenBuilder().env(NSPTestEnv.TEST1_DNSP)
                .keystoreFromClassPath("FMKOnlineBilletOmv-T.jks").keystorePassword("Test1234".toCharArray())
                .fromXml(xml).build();

        IdentityToken idwsToken = bst.exchangeToIdentityToken("https://fmk", "0501792275", "1111111118");

        // Extract priviledge attribibute, base64 decode it, and verify that our
        // procuration cpr is there
        Element attributeStatement = XmlUtil.getChild(idwsToken.assertion, NsPrefixes.saml, "AttributeStatement");
        String privsBase64 = SamlUtil.getSamlAttribute(attributeStatement,
                "dk:gov:saml:attribute:Privileges_intermediate");
        String privs = new String(Base64.getDecoder().decode(privsBase64), StandardCharsets.UTF_8);

        Document doc = XmlUtil.getDocBuilder().parse(new ByteArrayInputStream(privs.getBytes(StandardCharsets.UTF_8)));

        XPathContext xpath = new XPathContext(doc);
        Element privileges = xpath.findElement(doc.getDocumentElement(), "/" + NsPrefixes.bpp.name() + ":PrivilegeList/"
                + NsPrefixes.bpp.name() + ":PrivilegeGroup");

        assertEquals("urn:dk:healthcare:saml:actThroughProcurationBy:cprNumberIdentifier:1111111118",
                privileges.getAttribute("Scope"));
    }

    @Test
    void cannotExchangeObsoleteBootstrapTokenToIDWSToken() throws Exception {

        String xml = readFromClasspath("/bootstrap-token.xml");

        BootstrapToken bst = new BootstrapTokenBuilder().env(NSPTestEnv.TEST1_DNSP)
                .keystoreFromClassPath("FMKOnlineBilletOmv-T.jks").keystorePassword("Test1234".toCharArray())
                .fromXml(xml).build();

        assertThrows(STSInvocationException.class, () -> {
            bst.exchangeToIdentityToken("https://fmk", "0501792275");
        });

    }

    @Test
    void cannotExchangeObsoleteJWTTokenToIDWSToken() throws Exception {

        String jwt = "eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJxMjJJMVdlYkp2T09WTVNDblF5NlBqX1NqWFpLTENCajNfaVF2OXV3YWJNIn0.eyJleHAiOjE2NDkzMzc1MDMsIm5iZiI6MCwiaWF0IjoxNjQ5MzMzOTAzLCJhdXRoX3RpbWUiOjE2NDkzMzM5MDIsImp0aSI6IjZjZGJlMWVkLTRjYTQtNDBmNy05YjgyLTI0NWFhYWFmNDBhOSIsImlzcyI6Imh0dHBzOi8vb2lkYy10ZXN0LnN1bmRoZWRzZGF0YXN0eXJlbHNlbi5kay9hdXRoL3JlYWxtcy9zZHMiLCJhdWQiOlsiZm1rX21vY2siLCJhY2NvdW50Il0sInN1YiI6ImIwNjk5OGM1LTNkMGUtNDlkMi05MmJkLTY3ODk4MDlkYmU1YSIsInR5cCI6IkJlYXJlciIsImF6cCI6ImZta19tb2NrIiwibm9uY2UiOiJBdm5DbVMxcThpemJWVTNKdUg3ZXZ3Iiwic2Vzc2lvbl9zdGF0ZSI6ImM1M2QyNzllLTg2MzQtNDI1Ny1iNzc3LWI0NGRkYzFmZjFhOCIsImFjciI6IjEiLCJyZWFsbV9hY2Nlc3MiOnsicm9sZXMiOlsib2ZmbGluZV9hY2Nlc3MiLCJ1bWFfYXV0aG9yaXphdGlvbiJdfSwicmVzb3VyY2VfYWNjZXNzIjp7ImFjY291bnQiOnsicm9sZXMiOlsibWFuYWdlLWFjY291bnQiLCJtYW5hZ2UtYWNjb3VudC1saW5rcyIsInZpZXctcHJvZmlsZSJdfX0sInNjb3BlIjoib3BlbmlkIGZtayBvZmZsaW5lX2FjY2VzcyBzb3NpLXN0cyBwcm9maWxlIiwic2lkIjoiYzUzZDI3OWUtODYzNC00MjU3LWI3NzctYjQ0ZGRjMWZmMWE4IiwiY3ByIjoiMDEwMTAxMDEwMSIsInByZWZlcnJlZF91c2VybmFtZSI6InBpZC0wMTAxMDEwMTAxLWF1dG8ifQ.VFGy7SWTy_Vmooj-aqQS3XgRgkhDut1jEq3sdKIOxz_guH5G-LIfMGsl0SUkds2R2unm4B-xynPwjqvbx2aBfbgW8cJFPpJH5Pxl9j0XxXktOZVEjPSz2MlNsK3Ln-h9Avz9PshCZ1xYfuiNIK2bhFw2Wa21mCLkUFMGrOrfMTlR9dwOi0M24PoDsa8awoIMQn-BOP6rYaMQTfQzzKsqfhwe9H0Un1fiFPejgR8Gv9wi5MISlt7-7ehnQC8vyLzfcF-_aW2sylv68FzefEudxkuhjVkm08WCa3jxYkVP4PUxTY6FfhT-bKrmpnw0lPIbt0U7-i4F74YeYxfltg4EEQ";

        BootstrapToken bst = new BootstrapTokenBuilder().env(NSPTestEnv.TEST1_DNSP)
                .keystoreFromClassPath("FMKOnlineBilletOmv-T.jks").keystorePassword("Test1234".toCharArray())
                .fromJwt(jwt).build();

        STSInvocationException e = assertThrows(STSInvocationException.class, () -> {
            bst.exchangeToIdentityToken("https://fmk", "0501792275");
        });

        assertTrue(e.getMessage().contains("expired"));
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