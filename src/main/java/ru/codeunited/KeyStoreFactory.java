package ru.codeunited;

import sun.security.tools.keytool.CertAndKeyGen;
import sun.security.x509.X500Name;

import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.util.UUID;

public class KeyStoreFactory {

    private static final KeyStoreFactory INSTANCE = new KeyStoreFactory();

    private static final String PROVIDER = "BC";

    public static KeyStoreFactory getInstance() {
        return INSTANCE;
    }

    public KeyStore newKeyStore(
            String keyAlias,
            char[] keystorePassword,
            char[] keyPassword,
            CertAndKeyGen certAndKeyGen,
            int keyLength,
            X500Name dn) throws Exception {

        KeyStore keystore = KeyStore.getInstance(KeyStore.getDefaultType());
        keystore.load(null, keystorePassword);
        certAndKeyGen.generate(keyLength);
        long validSecs = (long) 365 * 24 * 60 * 60;
        X509Certificate cert = certAndKeyGen.getSelfCertificate(dn, validSecs);
        keystore.setKeyEntry(keyAlias, certAndKeyGen.getPrivateKey(), keyPassword, new X509Certificate[]{cert});
        return keystore;
    }

    public KeyStore newKeyStoreSHA256WithRSA2048(
            String keyAlias,
            char[] keystorePassword,
            char[] keyPassword) throws Exception {

        CertAndKeyGen certGen = new CertAndKeyGen("RSA", "SHA256WithRSA", PROVIDER);
        X500Name dn = new X500Name("CN=My Application,O=" + UUID.randomUUID().toString() + ",L=My City,C=DE");
        return newKeyStore(keyAlias, keystorePassword, keyPassword, certGen, 2048, dn);
    }

}
