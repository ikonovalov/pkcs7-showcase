package ru.codeunited;

import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cms.*;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.util.Selector;
import org.bouncycastle.util.Store;
import sun.misc.BASE64Encoder;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Base64;
import java.util.Iterator;

import static java.nio.charset.StandardCharsets.UTF_8;

public class CMS {

    private static String myXml = "<abc><element1>123</element1></abc>";

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    public static void main(String[] args) throws Exception {


        // Signer 1
        Organization org1 = new Organization();
        X509Certificate cert1 = org1.cert();
        SignerInfoGenerator siGen1 = org1.createSignerInfoGenerator();

        // Signer 2
        Organization org2 = new Organization();
        X509Certificate cert2 = org2.cert();
        SignerInfoGenerator siGen2 = org2.createSignerInfoGenerator(() -> {
                    ASN1EncodableVector v = new ASN1EncodableVector();
                    v.add(new Attribute(new ASN1ObjectIdentifier("1.2.643.113549.1.9"), new DERSet(new DEROctetString(new byte[]{1, 2, 3}))));
                    AttributeTable extra = new AttributeTable(v);
                    return new DefaultSignedAttributeTableGenerator(extra);
                },
                () -> null);

        X509Certificate[] certs = new X509Certificate[]{cert1, cert2};
        SignerInfoGenerator[] siGenerator = new SignerInfoGenerator[]{siGen1, siGen2};

        CMSSignedData sigData = signData(myXml.getBytes(UTF_8), certs, siGenerator);

        BASE64Encoder encoder = new BASE64Encoder();

        String signedContent = encoder.encode((byte[]) sigData.getSignedContent().getContent());
        System.out.println("(" + signedContent.length() + ") Content: " + signedContent + "\n");

        String envelopedData = encoder.encode(sigData.getEncoded());
        System.out.println("(" + envelopedData.length() + ") SignedData: " + envelopedData);


        // READ CONTENT
        byte[] incomingContent = sigData.getEncoded();
        System.out.println("\n" + readContent(incomingContent));

    }

    private static String readContent(byte[] signedData) throws IOException, CMSException {
        ByteArrayInputStream inputStream = new ByteArrayInputStream(signedData);
        ASN1InputStream asnInputStream = new ASN1InputStream(inputStream);
        CMSSignedData cmsSignedData = new CMSSignedData(ContentInfo.getInstance(asnInputStream.readObject()));

        Store<X509CertificateHolder> certificates = cmsSignedData.getCertificates();

        System.out.println("\n\n");
        cmsSignedData.getSignerInfos().getSigners().forEach(signer -> {

            Selector<X509CertificateHolder> certSelector = new X509SerialNumberSelector(signer);

            // expected exact match
            Iterator<X509CertificateHolder> matches = certificates.getMatches(certSelector).iterator();
            boolean verified;
            try {
                verified = signer.verify(new JcaSimpleSignerInfoVerifierBuilder().setProvider("BC").build(matches.next()));
            } catch (CMSException | OperatorCreationException | CertificateException e) {
                e.printStackTrace();
                verified = false;
            }

            System.out.println((verified ? "VALID" : "INVALID") + " <= Signature: " + Base64.getEncoder().encodeToString(
                    signer.toASN1Structure().getEncryptedDigest().getOctets()
            ));
        });
        System.out.println("\n\n");

        byte[] byteContent = (byte[]) cmsSignedData.getSignedContent().getContent();
        return new String(byteContent, UTF_8);
    }

    private static CMSSignedData signData(byte[] data, X509Certificate[] signingCertificate, SignerInfoGenerator[] generators) throws Exception {
        CMSTypedData cmsData = new CMSProcessableByteArray(data);

        CMSSignedDataGenerator cmsGenerator = new CMSSignedDataGenerator();
        Arrays.asList(generators).forEach(cmsGenerator::addSignerInfoGenerator);

        Store certs = new JcaCertStore(Arrays.asList(signingCertificate));
        cmsGenerator.addCertificates(certs);

        return cmsGenerator.generate(cmsData, true);
    }

}
