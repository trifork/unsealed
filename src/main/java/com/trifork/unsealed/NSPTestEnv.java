package com.trifork.unsealed;

public enum NSPTestEnv implements NSPEnv {
    TEST1_CNSP("http://test1-cnsp.ekstern-test.nspop.dk:8080"),
    TEST1_DNSP("http://test1.ekstern-test.nspop.dk:8080"),
    TEST2_CNSP("http://test2-cnsp.ekstern-test.nspop.dk:8080"),
    TEST2_DNSP("http://test2.ekstern-test.nspop.dk:8080"),
    PRODTEST_CNSP("http://prodtest-cnsp.ekstern-test.nspop.dk:8080"),
    PRODTEST_DNSP("http://prodtest.ekstern-test.nspop.dk:8080"),
    UDD_CNSP("http://uddannelse-cnsp.ekstern-test.nspop.dk:8080"),
    UDD_DNSP("http://uddannelse.ekstern-test.nspop.dk:8080");

    private String stsBaseUrl;

    NSPTestEnv(String stsBaseUrl) {
        this.stsBaseUrl = stsBaseUrl;
    }

    @Override
    public String getStsBaseUrl() {
        return stsBaseUrl;
    }
}
