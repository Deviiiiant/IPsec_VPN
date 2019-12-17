package HandshakeHelper;

import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Base64;

public class CrtTransfer {

    /*get certificate from file*/
    public static X509Certificate getCertificateFromFile(String crt)
            throws FileNotFoundException, CertificateException {
        FileInputStream fi = new FileInputStream(crt);
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        return (X509Certificate) cf.generateCertificate(fi);
    }

    /*get certificate from String*/
    public static X509Certificate gerCertificateFromString(String crt)
            throws CertificateException {
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        byte[] crtbyte = Base64.getDecoder().decode(crt);
        return (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(crtbyte));
    }


    /* convert certificate to String*/
    public static String crtFileToString (String crt)
            throws FileNotFoundException, CertificateException {
        X509Certificate certificate = getCertificateFromFile(crt);
        return Base64.getEncoder().encodeToString(certificate.getEncoded());
    }
}
