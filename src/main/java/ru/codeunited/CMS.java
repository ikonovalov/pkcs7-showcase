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
import java.security.Security;
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

        byte[] transmissionChannel = null;

        // Signer 1
        {
            Organization org1 = new Organization();
            X509Certificate cert1 = org1.cert();

            SignerInfoGenerator siGen1 = org1.createSignerInfoGenerator();


            X509Certificate[] certs = new X509Certificate[]{cert1};
            SignerInfoGenerator[] siGenerator = new SignerInfoGenerator[]{siGen1};

            CMSSignedData sigData = signData(myXml.getBytes(UTF_8), certs, siGenerator);

            BASE64Encoder encoder = new BASE64Encoder();

            String signedContent = encoder.encode((byte[]) sigData.getSignedContent().getContent());
            System.out.println("(" + signedContent.length() + ") Content: " + signedContent + "\n");

            String envelopedData = encoder.encode(sigData.getEncoded());
            System.out.println("(" + envelopedData.length() + ") SignedData: " + envelopedData);
            byte[] incomingContent = sigData.getEncoded();
            transmissionChannel = incomingContent;

        }

        // TRANSFER SOME BYTES VIA transmissionChannel

        // ================================================================================================
        // Second signer
        {
            System.out.println("\n" + readContent(transmissionChannel));

            CMSSignedData cms = signedDataFrom(transmissionChannel);
            CMSTypedData cmsData = cms.getSignedContent();

            // Signer 2
            Organization org2 = new Organization();
            X509Certificate cert2 = org2.cert();

            CMSSignedDataGenerator cmsGenerator = new CMSSignedDataGenerator();

            SignerInfoGenerator siGen2 = org2.createSignerInfoGenerator(
                    () -> { // signed attributes
                        ASN1EncodableVector v = new ASN1EncodableVector();
                        v.add(new Attribute(new ASN1ObjectIdentifier("1.2.643.113549.1.9.9"), new DERSet(new DEROctetString(new byte[]{1, 2, 3}))));
                        AttributeTable extra = new AttributeTable(v);
                        return new DefaultSignedAttributeTableGenerator(extra);
                    },
                    () -> { // unsigned attributes

                        // FIXME: IT WORKS INCORRECTLY
                        // counter signature
                        /*
                        SignerInformation origSigner = (SignerInformation) cms.getSignerInfos().getSigners().toArray()[0];
                        SignerInformationStore counterSignature = null;
                        try {
                            counterSignature = cmsGenerator.generateCounterSigners(origSigner);
                        } catch (CMSException e) {
                            e.printStackTrace();
                        }
                        SignerInformation counterSig = SignerInformation.addCounterSigners(origSigner, counterSignature);
                        AttributeTable extra = new AttributeTable(new Attribute(CMSAttributes.counterSignature, new DERSet(counterSig.toASN1Structure())));
                        return new SimpleAttributeTableGenerator(extra);
                        */
                        return null;
                    });


            // restore old ============
            cmsGenerator.addSigners(cms.getSignerInfos());
            cmsGenerator.addCertificates(cms.getCertificates());
            // ========================

            cmsGenerator.addSignerInfoGenerator(siGen2);

            Store<X509Certificate> certsStore = new JcaCertStore(
                    Arrays.asList(new X509Certificate[]{cert2})
            );
            cmsGenerator.addCertificates(certsStore);

            CMSSignedData regenerated = cmsGenerator.generate(cmsData, true);
            verify(regenerated);
            System.out.println("Done");

        }


    }

    private static String readContent(byte[] signedData) throws IOException, CMSException {
        CMSSignedData cmsSignedData = signedDataFrom(signedData);

        verify(cmsSignedData);

        byte[] byteContent = (byte[]) cmsSignedData.getSignedContent().getContent();
        return new String(byteContent, UTF_8);
    }

    private static void verify(CMSSignedData cmsSignedData) {
        Store<X509CertificateHolder> certificates = cmsSignedData.getCertificates();

        System.out.println("\n\n");
        cmsSignedData.getSignerInfos().getSigners().forEach(signer -> {

            Selector<X509CertificateHolder> certSelector = new X509SerialNumberSelector(signer);

            // expected exact match
            Iterator<X509CertificateHolder> matches = certificates.getMatches(certSelector).iterator();
            boolean verified;
            try {
                X509CertificateHolder certHolder = matches.next();
                System.out.println(certHolder.getSubject());
                verified = signer.verify(new JcaSimpleSignerInfoVerifierBuilder().setProvider("BC").build(certHolder));
            } catch (CMSException | OperatorCreationException | CertificateException e) {
                e.printStackTrace();
                verified = false;
            }

            byte[] signatureOctets = signer.toASN1Structure().getEncryptedDigest().getOctets();
            String valStr = verified ? "VALID" : "INVALID";
            System.out.println(valStr + " <= Signature: " + Base64.getEncoder().encodeToString(signatureOctets));
        });
        System.out.println("\n\n");
    }

    private static CMSSignedData signedDataFrom(byte[] signedData) throws CMSException, IOException {
        ByteArrayInputStream inputStream = new ByteArrayInputStream(signedData);
        ASN1InputStream asnInputStream = new ASN1InputStream(inputStream);
        return new CMSSignedData(ContentInfo.getInstance(asnInputStream.readObject()));
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
