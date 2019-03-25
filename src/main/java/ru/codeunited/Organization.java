package ru.codeunited;

import org.bouncycastle.cms.CMSAttributeTableGenerator;
import org.bouncycastle.cms.SignerInfoGenerator;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;

import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.Optional;
import java.util.function.Supplier;

class Organization {

    private static final String ALIAS = "A-1";

    private static final String SHA_256_WITH_RSA = "SHA256withRSA";

    private static char[] PRIVATE_KEY_PASSWORD = "0987654321".toCharArray();

    private static char[] KEYSTORE_PASSWORD = "1234567890".toCharArray();

    private KeyStore keyStore;

    Organization() throws Exception {
        this(KeyStoreFactory.getInstance().newKeyStoreSHA256WithRSA2048(ALIAS, KEYSTORE_PASSWORD, PRIVATE_KEY_PASSWORD));
    }

    private Organization(KeyStore keyStore) {
        this.keyStore = keyStore;
    }

    X509Certificate cert() throws Exception {
        return (X509Certificate) keyStore.getCertificate(ALIAS);
    }

    private PrivateKey key() throws Exception {
        return (PrivateKey) keyStore.getKey(ALIAS, PRIVATE_KEY_PASSWORD);
    }

    private DigestCalculatorProvider digestCalculatorProvider() throws OperatorCreationException {
        return new JcaDigestCalculatorProviderBuilder().setProvider("BC").build();
    }

    SignerInfoGenerator createSignerInfoGenerator() throws Exception {
        Supplier<CMSAttributeTableGenerator> $null = () -> null;
        return createSignerInfoGenerator($null, $null);
    }

    SignerInfoGenerator createSignerInfoGenerator(
            Supplier<CMSAttributeTableGenerator> signedAttributesGenerator,
            Supplier<CMSAttributeTableGenerator> unsignedAttributesGenerator) throws Exception {

        DigestCalculatorProvider digestProvider = digestCalculatorProvider();

        PrivateKey signingKey = key();

        X509Certificate signingCert = cert();

        ContentSigner contentSigner = new JcaContentSignerBuilder(SHA_256_WITH_RSA).build(signingKey);

        JcaSignerInfoGeneratorBuilder jcaSignerInfoGeneratorBuilder = new JcaSignerInfoGeneratorBuilder(digestProvider);

        Optional.ofNullable(signedAttributesGenerator.get()).ifPresent(jcaSignerInfoGeneratorBuilder::setSignedAttributeGenerator);
        Optional.ofNullable(unsignedAttributesGenerator.get()).ifPresent(jcaSignerInfoGeneratorBuilder::setUnsignedAttributeGenerator);

        return jcaSignerInfoGeneratorBuilder
                .build(contentSigner, signingCert);

    }
}
