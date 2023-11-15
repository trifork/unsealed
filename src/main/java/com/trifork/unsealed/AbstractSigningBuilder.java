package com.trifork.unsealed;

public abstract class AbstractSigningBuilder<ParamsType extends AbstractSigningBuilderParams> {

    protected ParamsType params;

    protected AbstractSigningBuilder(ParamsType params) {
        this.params = params;
    }

    protected void validateParameters() {
    }
}
