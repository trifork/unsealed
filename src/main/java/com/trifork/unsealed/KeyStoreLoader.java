package com.trifork.unsealed;

import static com.trifork.unsealed.KeystoreUtil.guessKeystoreType;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.Objects;
import java.util.stream.Stream;

/**
 * KeyStoreLoader is an immutable builder that loads a public/private certificate keypair into an instance of {@link com.trifork.unsealed.CertAndKey}. 
 * 
 * @author Jeppe Sommer
 */
public class KeyStoreLoader {
    private KeyStoreLoaderParams params;

    /**
     * Create a blank builder instance. 
     */
    public KeyStoreLoader() {
        this(new KeyStoreLoaderParams());
    }

    private KeyStoreLoader(KeyStoreLoaderParams keyPairLoaderParams) {
        this.params = keyPairLoaderParams;
    }

    /**
     * Load from a keystore found on the class path.
     * @param path The path into the class path 
     * @return A new immutable builder instance that encapsulates the supplied parameter
     */
    public KeyStoreLoader fromClassPath(String path) {
        var params = this.params.copy();
        params.fromClassPath = path;
        return new KeyStoreLoader(params);
    }

    /**
     * Load from a keystore found in the file system.
     * @param path The file system path 
     * @return A new immutable builder instance that encapsulates the supplied parameter
     */
    public KeyStoreLoader fromFilePath(String path) {
        var params = this.params.copy();
        params.fromFilePath = path;
        return new KeyStoreLoader(params);
    }

    /**
     * Load from a keystore supplied as an InputStream.
     * @param inputStream The {@link java.io.InputStream}
     * @return A new immutable builder instance that encapsulates the supplied parameter
     */
    public KeyStoreLoader fromInputStream(InputStream inputStream) {
        var params = this.params.copy();
        params.fromInputStream = inputStream;
        return new KeyStoreLoader(params);
    }

    /**
     * Load from a {@link java.security.KeyStore} instance.
     * @param keyStore The keystore
     * @return A new immutable builder instance that encapsulates the supplied parameter
     */
    public KeyStoreLoader fromKeyStore(KeyStore keyStore) {
        var params = this.params.copy();
        params.keyStore = keyStore;
        return new KeyStoreLoader(params);
    }

    /**
     * Specify the type of keystore. This is necessary when an inputstream is supplied, in which case
     * there is no name to infer the keystore type from. 
     * @param type The keystore type ("JKS" or "PKCS12")
     * @return A new immutable builder instance that encapsulates the supplied parameter
     */
    public KeyStoreLoader type(String type) {
        var params = this.params.copy();
        params.type = type;
        return new KeyStoreLoader(params);
    }

    /**
     * Specify a password for accessing the keystore.
     * @param password The keystore password as a char array
     * @return A new immutable builder instance that encapsulates the supplied parameter
     */
    public KeyStoreLoader password(char[] password) {
        var params = this.params.copy();
        params.password = password;
        return new KeyStoreLoader(params);
    }

    /**
     * Specify a password for accessing the keystore.
     * @param password The keystore password as a {@link java.lang.String}
     * @return A new immutable builder instance that encapsulates the supplied parameter
     */
    public KeyStoreLoader password(String password) {
        return this.password(password.toCharArray());
    }

    /**
     * Specify a keystore alias. This may be necessary in cases where a keystore holds multiple keys. 
     * @param alias The alias
     * @return A new immutable builder instance that encapsulates the supplied parameter
     */
    public KeyStoreLoader alias(String alias) {
        var params = this.params.copy();
        params.alias = alias;
        return new KeyStoreLoader(params);
    }

    /**
     * Load a {@link CertAndKey} from the supplied parameters.
     * @return
     * @throws KeyStoreException
     * @throws NoSuchAlgorithmException
     * @throws CertificateException
     * @throws IOException
     * @throws UnrecoverableKeyException
     */
    public CertAndKey load() throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException, UnrecoverableKeyException {

        validateParameters();

        InputStream keystoreIs = null;
        String keystoreType = params.type;

        KeyStore ks;
        if (params.keyStore != null) {
            ks = params.keyStore;
        } else {
            if (params.fromInputStream != null) {
                keystoreIs = params.fromInputStream;
            } else if (params.fromClassPath != null) {
                keystoreIs = Thread.currentThread().getContextClassLoader().getResourceAsStream(params.fromClassPath);
                if (keystoreType == null) {
                    keystoreType = guessKeystoreType(params.fromClassPath);
                }
            } else if (params.fromFilePath != null) {
                keystoreIs = new FileInputStream(new File(params.fromFilePath));
                if (keystoreType == null) {
                    keystoreType = guessKeystoreType(params.fromFilePath);
                }
            }

            ks = KeyStore.getInstance(keystoreType);
            ks.load(keystoreIs, params.password);
        }

        String alias = params.alias != null ? params.alias : ks.aliases().nextElement();

        X509Certificate certificate = (X509Certificate) ks.getCertificate(alias);

        if (certificate == null) {
            throw new IllegalArgumentException("No certificate found with alias \"" + alias + "\", found " + Collections.list(ks.aliases()));
        }

        certificate.checkValidity();

        PrivateKey privateKey = (PrivateKey) ks.getKey(alias, params.password);
        
        return new CertAndKey(certificate, privateKey);
    }

    private void validateParameters() {
        if (Stream.of(params.fromClassPath, params.fromFilePath, params.fromInputStream, params.keyStore).filter(Objects::nonNull).count() != 1) {
            throw new IllegalStateException("Exactly one of [fromClassPath, fromFilePath, fromInputStream, keystore] must be specified");
        }

        if (params.fromInputStream != null && params.type == null) {
            throw new IllegalStateException("When keystoreFromInputStream is specified, keystoreType must also be specified");
        }

        if (params.password == null) {
            throw new IllegalStateException("No password specified");
        }
    }

}
