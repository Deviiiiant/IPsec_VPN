package HandshakeMessages;

import HandshakeHelper.CrtTransfer;
import java.io.FileNotFoundException;
import java.security.cert.CertificateException;

public class ClientHello extends HandshakeMessage {

    public ClientHello(){
        this.putParameter("MessageType","ClientHello");
    }

    public void putCrtIn(String argCrtFile)
            throws FileNotFoundException, CertificateException {

        this.putParameter("Certificate", CrtTransfer.crtFileToString(argCrtFile));
    }

}
