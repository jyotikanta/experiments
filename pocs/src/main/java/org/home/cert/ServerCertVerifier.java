package org.home.cert;

import org.home.cert.custom.CustomSSLSocketFactory;
import org.home.cert.exceptions.UntrustedCertException;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLPeerUnverifiedException;
import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;
import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;

public class ServerCertVerifier
{
    public static void main(String[] args) throws Exception
    {
        init();
        try
        {
            //Call server and get Certificate
            URL url;
            /*if(args.length > 1)
            {
                url = args[0];
            }
            */
            url = new URL("https://xyz.ai/");
            //URL url = new URL("https://www.google.com/");
            HttpsURLConnection connection = (HttpsURLConnection) url.openConnection();
            connection.setConnectTimeout(10000);
            connection.connect();
            Certificate[] certChain = connection.getServerCertificates();
            System.out.println("Certificate verified successfully");
            System.out.println(certChain[0]);
        }
        catch (MalformedURLException e)
        {
            throw new RuntimeException(e);
        }
        catch (SSLPeerUnverifiedException e)
        {
            throw new RuntimeException(e);
        }
        catch (IOException e)
        {
            if(e.getMessage().contains("unable to find valid certification path to requested target"))
            {
                UntrustedCertException untrustedCertException = (UntrustedCertException)e.getCause();
                X509Certificate[] chain = untrustedCertException.getChain();
                System.out.println("Untrusted Certificate Received...");
                System.out.println(chain[0]);
            }
        }
    }

    private static void init() throws NoSuchAlgorithmException, KeyStoreException, KeyManagementException
    {
        HttpsURLConnection.setDefaultSSLSocketFactory(new CustomSSLSocketFactory());
    }
}
