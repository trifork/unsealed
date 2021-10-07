package com.trifork.unsealed;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.FileReader;
import java.security.Key;
import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.time.LocalDateTime;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

public class OIOSamlTest extends AbstractTest {
    private static final String KEYSTORE_PASSWORD = "Test1234";
    private static X509Certificate idpCert;
    private static Key idpPrivateKey;

    @BeforeEach
    void setup0() throws Exception {
        Logger.getLogger(AbstractTest.class.getName()).log(Level.FINE, "1");
        KeyStore idpKeyStore = KeyStore.getInstance("PKCS12");
        Logger.getLogger(AbstractTest.class.getName()).log(Level.FINE, "2");
        idpKeyStore.load(BootstrapTokenHelper.class.getResourceAsStream("/TestTrustedIdpForBootstrapToken.p12"),
                "Test1234".toCharArray());

        AbstractTest.setup();
        Logger.getLogger(AbstractTest.class.getName()).log(Level.FINE, "3");

        idpCert = (X509Certificate) idpKeyStore.getCertificate(idpKeyStore.aliases().nextElement());
        idpPrivateKey = idpKeyStore.getKey(idpKeyStore.aliases().nextElement(), "Test1234".toCharArray());
        Logger.getLogger(AbstractTest.class.getName()).log(Level.FINE, "4");
    }

    @Test
    void canExchangeOIOSAMLTokenToIdCard() throws Exception {
        // String assertion = null;
        // try (var reader = new FileReader("u:/projects/unsealed/src/test/resources/assertion.xml")) {
        //     char[] chars = new char[1024*1024];
        //     int count = reader.read(chars);
        //     assertion = new String(chars, 0, count);
        // }

        String assertion = OIOSamlTokenHelper.createSamlToken(idpCert, idpPrivateKey,
                "C=DK,O=TRIFORK A/S // CVR:20921897,CN=Lars Larsen,Serial=CVR:20921897-RID:52723247");

        SAMLTokenBuilder samlTokenBuilder = new SAMLTokenBuilder();
        OIOSAMLToken samlToken = samlTokenBuilder.env(NSPTestEnv.TEST1_DNSP).keystoreFromClassPath("TRIFORK AS - FMK-online.jks")
                .keystorePassword(KEYSTORE_PASSWORD.toCharArray()).xml(assertion).build();

        IdCard exchangedIdCard = samlToken.exchangeToIdCard();
        assertNotNull(exchangedIdCard);

        String subjectName = exchangedIdCard.getSubjectName();
        assertEquals("0501792275", subjectName);

        String asString = exchangedIdCard.asString(false, false);
        assertTrue(asString.contains("Larsen"));
    }

}
