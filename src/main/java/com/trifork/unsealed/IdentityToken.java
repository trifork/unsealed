package com.trifork.unsealed;

import java.time.Instant;

import org.w3c.dom.Element;

public class IdentityToken {

    public final Element assertion;
    public final String audience;
    public final Instant created;
    public final Instant expires;

public IdentityToken(Element assertion, String audience, Instant created, Instant expires) {
        this.assertion = assertion;
        this.audience = audience;
        this.created = created;
        this.expires = expires;
	}

}
