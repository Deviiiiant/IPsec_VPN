package HandshakeHelper;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

public class HandshakeVerify {

    public static void verifyCrtString(String crt, X509Certificate caCert )
            throws CertificateException, NoSuchProviderException,
            NoSuchAlgorithmException, InvalidKeyException, SignatureException {

        X509Certificate certificate = CrtTransfer.gerCertificateFromString(crt);
        certificate.verify(caCert.getPublicKey());
    }
}
