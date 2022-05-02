package com.trifork.unsealed;

import java.time.ZonedDateTime;

import org.w3c.dom.Element;

public class IdentityTokenBuilder {

    private Element assertion;
    private String audience;
    private ZonedDateTime created;
    private ZonedDateTime expires;

    public IdentityTokenBuilder() {
    }

    private IdentityTokenBuilder(Element assertion, String audience, ZonedDateTime created, ZonedDateTime expires) {
        this.assertion = assertion;
        this.audience = audience;
        this.created = created;
        this.expires = expires;
    }

    public IdentityTokenBuilder assertion(Element assertion) {
        return new IdentityTokenBuilder(assertion, audience, created, expires);
    }

    public IdentityTokenBuilder created(ZonedDateTime created) {
        return new IdentityTokenBuilder(assertion, audience, created, expires);
    }

    public IdentityTokenBuilder expires(ZonedDateTime expires) {
        return new IdentityTokenBuilder(assertion, audience, created, expires);
    }

    public IdentityTokenBuilder audience(String audience) {
        return new IdentityTokenBuilder(assertion, audience, created, expires);
    }

    public IdentityToken build() {
        return new IdentityToken(assertion, audience, created, expires);
    }
}
