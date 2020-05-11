package com.trifork.unsealed;

import java.time.Instant;

import org.w3c.dom.Element;

public class IdentityTokenBuilder {

    private Element assertion;
    private String audience;
    private Instant created;
    private Instant expires;

    public IdentityTokenBuilder() {
    }

    private IdentityTokenBuilder(Element assertion, String audience, Instant created, Instant expires) {
        this.assertion = assertion;
        this.audience = audience;
        this.created = created;
        this.expires = expires;
    }

    public IdentityTokenBuilder assertion(Element assertion) {
        return new IdentityTokenBuilder(assertion, audience, created, expires);
    }

    public IdentityTokenBuilder created(Instant created) {
        return new IdentityTokenBuilder(assertion, audience, created, expires);
    }

    public IdentityTokenBuilder expires(Instant expires) {
        return new IdentityTokenBuilder(assertion, audience, created, expires);
    }

    public IdentityTokenBuilder audience(String audience) {
        return new IdentityTokenBuilder(assertion, audience, created, expires);
    }

    public IdentityToken build() {
        return new IdentityToken(assertion, audience, created, expires);
    }
}
