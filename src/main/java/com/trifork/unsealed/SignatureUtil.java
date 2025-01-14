package com.trifork.unsealed;

import java.security.InvalidAlgorithmParameterException;
import java.security.Key;
import java.security.KeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.logging.Logger;

import javax.xml.crypto.AlgorithmMethod;
import javax.xml.crypto.KeySelector;
import javax.xml.crypto.KeySelectorException;
import javax.xml.crypto.KeySelectorResult;
import javax.xml.crypto.MarshalException;
import javax.xml.crypto.XMLCryptoContext;
import javax.xml.crypto.XMLStructure;
import javax.xml.crypto.dsig.CanonicalizationMethod;
import javax.xml.crypto.dsig.DigestMethod;
import javax.xml.crypto.dsig.Reference;
import javax.xml.crypto.dsig.SignatureMethod;
import javax.xml.crypto.dsig.SignedInfo;
import javax.xml.crypto.dsig.Transform;
import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.crypto.dsig.XMLSignatureException;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.dom.DOMSignContext;
import javax.xml.crypto.dsig.dom.DOMValidateContext;
import javax.xml.crypto.dsig.keyinfo.KeyInfo;
import javax.xml.crypto.dsig.keyinfo.KeyInfoFactory;
import javax.xml.crypto.dsig.keyinfo.KeyValue;
import javax.xml.crypto.dsig.keyinfo.X509Data;
import javax.xml.crypto.dsig.spec.C14NMethodParameterSpec;
import javax.xml.crypto.dsig.spec.TransformParameterSpec;

import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

public class SignatureUtil {
    static final Logger log = Logger.getLogger(SignatureUtil.class.getName());

    static final Map<String, String> URI_2_ALGO;
    static {
        URI_2_ALGO = new HashMap<>();
        URI_2_ALGO.put(SignatureMethod.DSA_SHA1, "DSA");
        URI_2_ALGO.put(SignatureMethod.RSA_SHA1, "RSA");
        URI_2_ALGO.put(SignatureMethod.DSA_SHA256, "DSA");
        URI_2_ALGO.put(SignatureMethod.RSA_SHA256, "RSA");
    }

    // Create a DOM XMLSignatureFactory that will be used to generate the enveloped signatures
    static XMLSignatureFactory xmlSignatureFactory = XMLSignatureFactory.getInstance("DOM");

    public static void sign(Element rootElement, Element nextSibling, String[] referenceUris, String signatureId,
            Certificate certificate, Key privateKey, boolean enveloped) throws NoSuchAlgorithmException,
            InvalidAlgorithmParameterException, MarshalException, XMLSignatureException {

        // Create a Reference to the enveloped document (in this case we are
        // signing the whole document, so a URI of "" signifies that) and
        // also specify the SHA256 digest algorithm and the ENVELOPED Transform.
        if (rootElement == null) {
            throw new IllegalArgumentException("rootElement cannot be null");
        }

        // Without this, canonicalisation/digest calculation is incorrect
        rootElement.getOwnerDocument().normalizeDocument();

        List<Transform> transforms = new ArrayList<>();
        if (enveloped) {
            transforms.add(xmlSignatureFactory.newTransform(Transform.ENVELOPED, (TransformParameterSpec) null));
        }
        transforms
                .add(xmlSignatureFactory.newTransform(CanonicalizationMethod.EXCLUSIVE, (TransformParameterSpec) null));

        ArrayList<Reference> references = new ArrayList<>();
        for (String referenceUri : referenceUris) {
            references.add(xmlSignatureFactory.newReference(referenceUri,
                    xmlSignatureFactory.newDigestMethod(DigestMethod.SHA256, null), transforms, null, null));
        }

        // Create the SignedInfo
        SignedInfo si = xmlSignatureFactory.newSignedInfo(
                xmlSignatureFactory.newCanonicalizationMethod(CanonicalizationMethod.EXCLUSIVE,
                        (C14NMethodParameterSpec) null),
                xmlSignatureFactory.newSignatureMethod(SignatureMethod.RSA_SHA256, null), references);

        KeyInfoFactory kif = xmlSignatureFactory.getKeyInfoFactory();

        X509Data xd = kif.newX509Data(Collections.singletonList(certificate));
        KeyInfo ki = kif.newKeyInfo(Collections.singletonList(xd));

        // Create a DOMSignContext and specify the DSA PrivateKey and
        // location of the resulting XMLSignature's parent element
        // DOMSignContext dsc = new DOMSignContext
        // (kp.getPrivate(), doc.getDocumentElement());
        DOMSignContext dsc = new DOMSignContext(privateKey, rootElement);

        if (nextSibling != null) {
            dsc.setNextSibling(nextSibling);
        }
        // Create the XMLSignature (but don't sign it yet)
        XMLSignature signature = xmlSignatureFactory.newXMLSignature(si, ki, null, signatureId, null);

        // Marshal, generate (and sign) the enveloped signature
        signature.sign(dsc);
    }

    public static String getDigestOfCertificate(Certificate certificate)
            throws NoSuchAlgorithmException, CertificateEncodingException {

        byte[] certAsBytes = certificate.getEncoded();

        byte[] hash = MessageDigest.getInstance("SHA-256").digest(certAsBytes);

        return Base64.getEncoder().encodeToString(hash);
    }

    public static void validate(Element signedElement, boolean allowUnsafeSignature) throws MarshalException, XMLSignatureException, ValidationException {

        // // Find Signature element
        NodeList nl = signedElement.getElementsByTagNameNS(XMLSignature.XMLNS, "Signature");
        if (nl.getLength() == 0) {
            throw new XMLSignatureException("Cannot find Signature element");
        }

        // Create a DOM XMLSignatureFactory that will be used to unmarshal the document containing the XMLSignature
        XMLSignatureFactory fac = XMLSignatureFactory.getInstance("DOM");

        // Create a DOMValidateContext and specify a KeyValue KeySelector and document context
        DOMValidateContext valContext = new DOMValidateContext(new KeyValueKeySelector(), nl.item(0));
        
        if (allowUnsafeSignature) {
            valContext.setProperty("org.jcp.xml.dsig.secureValidation", Boolean.FALSE);
        }

        // unmarshal the XMLSignature
        XMLSignature signature = fac.unmarshalXMLSignature(valContext);

        // Validate the XMLSignature (generated above)
        boolean coreValidity = signature.validate(valContext);

        // Check core validation status
        if (coreValidity == false) {
            StringBuilder sb = new StringBuilder();
            sb.append("Signature failed core validation. ");
            boolean sv = signature.getSignatureValue().validate(valContext);
            sb.append("Signature validation status: ").append(sv);
            // check the validation status of each Reference
            for (Reference ref: signature.getSignedInfo().getReferences()) {
                boolean refValid = ref.validate(valContext);
                sb.append("; ref[" + ref.getURI() + "] validity status: " + refValid);
            }
            throw new ValidationException(sb.toString());
        }
    }

    /**
     * KeySelector which retrieves the public key out of the KeyValue element and
     * returns it. NOTE: If the key algorithm doesn't match signature algorithm,
     * then the public key will be ignored.
     */
    private static class KeyValueKeySelector extends KeySelector {
        public KeySelectorResult select(KeyInfo keyInfo, KeySelector.Purpose purpose, AlgorithmMethod method,
                XMLCryptoContext context) throws KeySelectorException {

            if (keyInfo == null) {
                throw new KeySelectorException("Null KeyInfo object!");
            }

            SignatureMethod sm = (SignatureMethod) method;
            List<XMLStructure> list = keyInfo.getContent();

            for (int i = 0; i < list.size(); i++) {
                XMLStructure xmlStructure = (XMLStructure) list.get(i);
                if (xmlStructure instanceof KeyValue) {
                    PublicKey pk = null;
                    try {
                        pk = ((KeyValue) xmlStructure).getPublicKey();
                    } catch (KeyException ke) {
                        throw new KeySelectorException(ke);
                    }
                    // make sure algorithm is compatible with method
                    if (algEquals(sm.getAlgorithm(), pk.getAlgorithm())) {
                        return new SimpleKeySelectorResult(pk);
                    }
                } else if (xmlStructure instanceof X509Data) {
                    X509Data x509Data = (X509Data) xmlStructure;

                    Iterator<?> xi = x509Data.getContent().iterator();
                    while (xi.hasNext()) {
                        Object o = xi.next();

                        if (!(o instanceof X509Certificate))
                            continue;

                        X509Certificate certificate = (X509Certificate) o;
                        if (!isTrustedCertificate(certificate)) {
                            continue;
                        }

                        final PublicKey key = certificate.getPublicKey();
                        // make sure algorithm is compatible with method
                        if (algEquals(method.getAlgorithm(), key.getAlgorithm())) {
                            return new SimpleKeySelectorResult(key);
                        }
                    }
                }
            }
            throw new KeySelectorException("No KeyValue element found!");
        }

        private boolean isTrustedCertificate(X509Certificate certificate) {
            return true;
        }

        private static boolean algEquals(String algURI, String algName) {
            return algName.equals(URI_2_ALGO.get(algURI));
        }
    }

    private static class SimpleKeySelectorResult implements KeySelectorResult {
        private PublicKey pk;

        SimpleKeySelectorResult(PublicKey pk) {
            this.pk = pk;
        }

        public Key getKey() {
            return pk;
        }
    }
}