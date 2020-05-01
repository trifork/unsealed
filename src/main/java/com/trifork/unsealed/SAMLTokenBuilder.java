package com.trifork.unsealed;

public class SAMLTokenBuilder {
    private NSPEnv env;
    private String xml;

    public SAMLTokenBuilder() {
    }

    private SAMLTokenBuilder(NSPEnv env, String xml) {
        this.env = env;
        this.xml = xml;
    }

    public SAMLTokenBuilder env(NSPEnv env) {
        return new SAMLTokenBuilder(env, xml);
    }

    public SAMLTokenBuilder xml(String xml) {
        return new SAMLTokenBuilder(env, xml);
    }
}