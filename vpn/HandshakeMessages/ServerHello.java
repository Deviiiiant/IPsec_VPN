package HandshakeMessages;

import HandshakeHelper.CrtTransfer;

import java.io.FileNotFoundException;
import java.security.cert.CertificateException;

public class ServerHello extends HandshakeMessage {

    public ServerHello(){
        this.putParameter("MessageType", "ServerHello");
    }

    public void putCrtIn(String argCrtFile)
            throws FileNotFoundException, CertificateException {
        this.putParameter("Certificate", CrtTransfer.crtFileToString(argCrtFile));
    }

}
