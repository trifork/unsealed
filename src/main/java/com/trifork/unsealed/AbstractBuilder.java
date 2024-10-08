package com.trifork.unsealed;


public abstract class AbstractBuilder<ParamsType extends AbstractBuilderParams> {

    protected ParamsType params;

    protected AbstractBuilder(ParamsType params) {
        this.params = params;
    }

    protected void validateParameters() {
    }
}
