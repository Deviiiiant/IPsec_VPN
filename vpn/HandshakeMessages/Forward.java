package HandshakeMessages;

import HandshakeHelper.HandshakeCrypto;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

public class Forward extends HandshakeMessage {

    public Forward(){
        this.putParameter("MessageType","Forward");
    }

    public void encryptContent (Key key, String targethost, String targetport) throws IllegalBlockSizeException, InvalidKeyException, BadPaddingException, NoSuchAlgorithmException, NoSuchPaddingException {

        byte[] targethostbyte = targethost.getBytes();
        this.putParameter("TargetHost", HandshakeCrypto.encrypt(targethostbyte,key));
        byte[] targetportbyte = targetport.getBytes();
        this.putParameter("TargetPort",HandshakeCrypto.encrypt(targetportbyte,key));

    }

    public String decryptTargethost (Key key)
            throws IllegalBlockSizeException, InvalidKeyException, BadPaddingException, NoSuchAlgorithmException, NoSuchPaddingException {
        byte[] targethostByte = HandshakeCrypto.decrypt(this.getParameter("TargetHost"),key);
        return new String(targethostByte);
    }

    public String decryptTargetport(Key key) throws IllegalBlockSizeException, InvalidKeyException, BadPaddingException, NoSuchAlgorithmException, NoSuchPaddingException {
        byte[] targetportByte = HandshakeCrypto.decrypt(this.getParameter("TargetPort"),key);
        return new String(targetportByte);
    }
}
