package org.home.cert.exceptions;

import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

public class UntrustedCertException extends CertificateException
{
    private X509Certificate[] chain;
    public UntrustedCertException(Exception e, X509Certificate[] chain)
    {
        super(e);
        this.chain = chain;
    }

    public X509Certificate[] getChain()
    {
        return chain;
    }
}
