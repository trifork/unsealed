package com.trifork.unsealed;

public interface NSPEnv {
    /**
     * @return the stsBaseUrl
     */
    String getStsBaseUrl();

    static NSPEnv fromUrl(String stsBaseUrl) {
        return new NSPEnv() {

            @Override
            public String getStsBaseUrl() {
                return (stsBaseUrl);
            }
        };
    }

    public static final NSPEnv NETIC_PROD = fromUrl("http://cnsp-lb.cnsp.netic.dk:8080");
}
