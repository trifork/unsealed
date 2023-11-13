package com.trifork.unsealed;

import static com.trifork.unsealed.KeystoreUtil.guessKeystoreType;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.Objects;
import java.util.stream.Stream;

public abstract class AbstractSigningBuilder<ParamsType extends AbstractSigningBuilderParams> {

    
    protected ParamsType params;
    protected X509Certificate certificate;
    protected Key privateKey;

    protected AbstractSigningBuilder(ParamsType params) {
        this.params = params;
    }

    protected void loadKeyStore() throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException, UnrecoverableKeyException {

        validateParameters();

        InputStream keystoreIs = null;
        String keystoreTp = params.keystoreType;

        KeyStore ks;
        if (params.keystore != null) {
            ks = params.keystore;
        } else {
            if (params.keystoreFromInputStream != null) {
                keystoreIs = params.keystoreFromInputStream;
            } else if (params.keystoreFromClassPath != null) {
                keystoreIs = Thread.currentThread().getContextClassLoader().getResourceAsStream(params.keystoreFromClassPath);
                keystoreTp = guessKeystoreType(params.keystoreFromClassPath);
            } else if (params.keystoreFromFilePath != null) {
                keystoreIs = new FileInputStream(new File(params.keystoreFromFilePath));
                keystoreTp = guessKeystoreType(params.keystoreFromClassPath);
            }

            ks = KeyStore.getInstance(keystoreTp);
            ks.load(keystoreIs, params.keystorePassword);
        }

        String alias = params.keystoreAlias != null ? params.keystoreAlias : ks.aliases().nextElement();

        certificate = (X509Certificate) ks.getCertificate(alias);

        if (certificate == null) {
            throw new IllegalArgumentException("No certificate found with alias \"" + alias + "\", found " + Collections.list(ks.aliases()));
        }

        certificate.checkValidity();

        privateKey = ks.getKey(alias, params.keystorePassword);
    }

    private void validateParameters() {
        if (Stream.of(params.keystoreFromClassPath, params.keystoreFromFilePath, params.keystoreFromInputStream, params.keystore).filter(Objects::nonNull).count() != 1) {
            throw new IllegalStateException("Exactly one of [keystoreFromClassPath, keystoreFromFilePath, keystoreFromInputStream, keystore] must be specified");
        }

        if (params.keystoreFromInputStream != null && params.keystoreType == null) {
            throw new IllegalStateException("When keystoreFromInputStream is specified, keystoreType must also be specified");
        }
    }
}
