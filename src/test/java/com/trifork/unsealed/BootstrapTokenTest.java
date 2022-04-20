package com.trifork.unsealed;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;

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
        Logger.getLogger(AbstractTest.class.getName()).log(Level.FINE, "4");
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
        assertTrue(idwsToken.created.isBefore(Instant.now()));
        assertTrue(idwsToken.expires.isAfter(idwsToken.created.plusSeconds(5)));
    }

    @Test
    void postFixedRequest() throws Exception {
        String request = readFromClasspath("/exchange-bst-request-1.xml");
        String response = WSHelper.post(request,
                NSPTestEnv.TEST1_CNSP.getStsBaseUrl() + BootstrapToken.DEFAULT_BST_TO_ID_ENDPOINT, "Issue");
        System.out.println("response: " + response);
    }

    @Disabled
    @Test
    void cannotExchangeObsoleteBootstrapTokenToIDWSToken() throws Exception {

        String xml = readFromClasspath("/bootstrap-token.xml");

        BootstrapToken bst = new BootstrapTokenBuilder().env(NSPTestEnv.TEST1_DNSP)
                .keystoreFromClassPath("FMKOnlineBilletOmv-T.jks").keystorePassword("Test1234".toCharArray())
                .fromXml(xml).build();

        IdentityToken idwsToken = bst.exchangeToIdentityToken("https://fmk", "0501792275");

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