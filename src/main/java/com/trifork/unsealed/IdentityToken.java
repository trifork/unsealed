package com.trifork.unsealed;

import java.time.ZonedDateTime;

import org.w3c.dom.Element;

public class IdentityToken {

    public final Element assertion;
    public final String audience;
    public final ZonedDateTime created;
    public final ZonedDateTime expires;

public IdentityToken(Element assertion, String audience, ZonedDateTime created, ZonedDateTime expires) {
        this.assertion = assertion;
        this.audience = audience;
        this.created = created;
        this.expires = expires;
	}

}
