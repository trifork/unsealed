package com.trifork.unsealed;

import org.junit.jupiter.api.Test;

public class IDCardTest extends AbstractTest {
    private static final String KEYSTORE_PASSWORD = "Test1234";

    @Test
    void canSignIdCard() throws Exception {
        IdCardBuilder builder = new IdCardBuilder();
        IdCard idCard = builder.env(NSPTestEnv.TEST1_CNSP).keystoreFromClassPath("LarsLarsen.p12").keystorePassword(KEYSTORE_PASSWORD.toCharArray()).cpr("0501792275").role("role").occupation("occupation").authorizationCode("authid").systemName("systemname").build();
        idCard.sign();
    }

    @Test
    void canExchangeIdCardToOIOSAMLToken() throws Exception {
        IdCardBuilder builder = new IdCardBuilder();
        IdCard idCard = builder.env(NSPTestEnv.TEST1_DNSP).keystoreFromClassPath("LarsLarsen.p12").keystorePassword(KEYSTORE_PASSWORD.toCharArray()).cpr("0501792275").role("role").occupation("occupation").systemName("systemname").build();
        idCard.sign();

        idCard.exchangeToOIOSAMLToken("https://saml.test1.fmk.netic.dk/fmk/");
    }

    @Test
    void canExchangeOIOSAMLTokenToIdCard() throws Exception {
        // TODO
    }

    
}
