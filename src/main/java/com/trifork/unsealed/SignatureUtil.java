package com.trifork.unsealed;

import java.io.OutputStream;
import java.security.Key;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.List;

import javax.xml.crypto.dsig.CanonicalizationMethod;
import javax.xml.crypto.dsig.DigestMethod;
import javax.xml.crypto.dsig.Reference;
import javax.xml.crypto.dsig.SignatureMethod;
import javax.xml.crypto.dsig.SignedInfo;
import javax.xml.crypto.dsig.Transform;
import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.dom.DOMSignContext;
import javax.xml.crypto.dsig.keyinfo.KeyInfo;
import javax.xml.crypto.dsig.keyinfo.KeyInfoFactory;
import javax.xml.crypto.dsig.keyinfo.X509Data;
import javax.xml.crypto.dsig.spec.C14NMethodParameterSpec;
import javax.xml.crypto.dsig.spec.TransformParameterSpec;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.w3c.dom.Element;

public class SignatureUtil {
    static XMLSignatureFactory xmlSignatureFactory = XMLSignatureFactory.getInstance("DOM");

    static void sign(Element rootElement, String referenceUri, String signatureId, Certificate certificate, Key privateKey, OutputStream os)
            throws Exception {

        // Create a DOM XMLSignatureFactory that will be used to generate the
        // enveloped signature

        // Create a Reference to the enveloped document (in this case we are
        // signing the whole document, so a URI of "" signifies that) and
        // also specify the SHA256 digest algorithm and the ENVELOPED Transform.
        List<Transform> transforms = new ArrayList<>();
        transforms.add(xmlSignatureFactory.newTransform(Transform.ENVELOPED, (TransformParameterSpec) null));
        transforms.add(xmlSignatureFactory.newTransform(CanonicalizationMethod.EXCLUSIVE, (TransformParameterSpec) null));

        Reference ref = xmlSignatureFactory.newReference(referenceUri, xmlSignatureFactory.newDigestMethod(DigestMethod.SHA1, null), transforms, null,
                null);

        // Create the SignedInfo
        SignedInfo si = xmlSignatureFactory.newSignedInfo(
                xmlSignatureFactory.newCanonicalizationMethod(CanonicalizationMethod.EXCLUSIVE, (C14NMethodParameterSpec) null),
                xmlSignatureFactory.newSignatureMethod(SignatureMethod.RSA_SHA1, null), Collections.singletonList(ref));

        KeyInfoFactory kif = xmlSignatureFactory.getKeyInfoFactory();

        X509Data xd = kif.newX509Data(Collections.singletonList(certificate));
        KeyInfo ki = kif.newKeyInfo(Collections.singletonList(xd));

        // Create a DOMSignContext and specify the DSA PrivateKey and
        // location of the resulting XMLSignature's parent element
        // DOMSignContext dsc = new DOMSignContext
        // (kp.getPrivate(), doc.getDocumentElement());
        DOMSignContext dsc = new DOMSignContext(privateKey, rootElement);

        // Create the XMLSignature (but don't sign it yet)
        XMLSignature signature = xmlSignatureFactory.newXMLSignature(si, ki, null, signatureId, null);

        // Marshal, generate (and sign) the enveloped signature
        signature.sign(dsc);

        TransformerFactory tf = TransformerFactory.newInstance();
        Transformer trans = tf.newTransformer();
        trans.transform(new DOMSource(rootElement), new StreamResult(os));
    }

    public static String getDigestOfCertificate(Certificate certificate)
            throws NoSuchAlgorithmException, CertificateEncodingException {

        byte[] certAsBytes = certificate.getEncoded();

        byte[] hash = MessageDigest.getInstance("SHA-1").digest(certAsBytes);

//        return Base64.getMimeEncoder(Integer.MAX_VALUE, new byte[0]).encodeToString(hash);
        return Base64.getEncoder().encodeToString(hash);
    }
}