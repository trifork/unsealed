package com.trifork.unsealed;

public class KeystoreUtil {
    static String guessKeystoreType(String path) {
        return path.endsWith(".jks") ? "JKS" : "PKCS12";
    }

}
