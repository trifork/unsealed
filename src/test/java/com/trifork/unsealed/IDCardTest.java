package com.trifork.unsealed;

import java.util.logging.ConsoleHandler;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.logging.SimpleFormatter;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

public class IDCardTest {
    private static final String KEYSTORE_PASSWORD = "Test1234";

    @BeforeAll
    static void setup() {
        final ConsoleHandler consoleHandler = new ConsoleHandler();
        consoleHandler.setLevel(Level.FINEST);
        consoleHandler.setFormatter(new SimpleFormatter());

        final Logger dsig = Logger.getLogger("org.jcp.xml.dsig.internal");
        dsig.setLevel(Level.FINEST);
        dsig.addHandler(consoleHandler);

        final Logger security = Logger.getLogger("com.sun.org.apache.xml.internal.security");
        security.setLevel(Level.FINEST);
        security.addHandler(consoleHandler);
    }

    @Test
    void canSignIdCard() throws Exception {
        IdCardBuilder builder = new IdCardBuilder();
        IdCard idCard = builder.env(NSPTestEnv.TEST1_CNSP).keystoreFromClassPath("LarsLarsen.p12").keystorePassword(KEYSTORE_PASSWORD).cpr("0501792275").role("role").occupation("occupation").authorizationCode("authid").systemName("systemname").build();
        idCard.sign();
    }

    @Test
    void canExchangeToSAMLToken() throws Exception {
        IdCardBuilder builder = new IdCardBuilder();
        IdCard idCard = builder.env(NSPTestEnv.TEST1_DNSP).keystoreFromClassPath("LarsLarsen.p12").keystorePassword(KEYSTORE_PASSWORD).cpr("0501792275").role("role").occupation("occupation").systemName("systemname").build();
        idCard.sign();

        idCard.exchangeToSAMLToken("https://saml.test1.fmk.netic.dk/fmk/");
    }

}
