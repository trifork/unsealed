package com.trifork.unsealed;

/**
 * An enumeration representing known STS base urls in the 4 NSP test environments (test1, test2, udd, and prodtest). Each enum value may be used as an
 * alternative to {@link NSPEnv#fromUrl(String)}
 */
public enum NSPTestEnv implements NSPEnv {
    TEST1_CNSP("https://test1-cnsp.ekstern-test.nspop.dk:8443"),
    TEST1_DNSP("https://test1.ekstern-test.nspop.dk:8443"),
    TEST2_CNSP("https://test2-cnsp.ekstern-test.nspop.dk:8443"),
    TEST2_DNSP("https://test2.ekstern-test.nspop.dk:8443"),
    PRODTEST_CNSP("https://prodtest-cnsp.ekstern-test.nspop.dk:8443"),
    PRODTEST_DNSP("https://prodtest.ekstern-test.nspop.dk:8443"),
    UDD_CNSP("https://uddannelse-cnsp.ekstern-test.nspop.dk:8443"),
    UDD_DNSP("https://uddannelse.ekstern-test.nspop.dk:8443");

    private String stsBaseUrl;

    NSPTestEnv(String stsBaseUrl) {
        this.stsBaseUrl = stsBaseUrl;
    }

    @Override
    public String getStsBaseUrl() {
        return stsBaseUrl;
    }
}
