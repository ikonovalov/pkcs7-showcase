package ru.codeunited;

import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.util.Selector;

class X509SerialNumberSelector implements Selector<X509CertificateHolder> {
    private final SignerInformation signer;

    public X509SerialNumberSelector(SignerInformation signer) {
        this.signer = signer;
    }

    @Override
    public boolean match(X509CertificateHolder obj) {
        return signer.getSID().getSerialNumber().equals(obj.getSerialNumber());
    }

    @Override
    public Object clone() {
        return new X509SerialNumberSelector(signer);
    }
}
