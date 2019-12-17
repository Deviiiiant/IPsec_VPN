package HandshakeMessages;

import HandshakeHelper.HandshakeCrypto;
import SessionCrypto.SessionEncrypter;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;

public class Session extends HandshakeMessage {

    public Session(){
        this.putParameter("MessageType","Session");
    }

    public void encryptContent(SessionEncrypter sessionEncrypter,
                               Key key, String SessionHost, int SessionPort)
            throws IllegalBlockSizeException, InvalidKeyException,
            BadPaddingException, NoSuchAlgorithmException, NoSuchPaddingException {

        /*encrypt session key*/
        byte[] keybyte = sessionEncrypter.getSessionKey().getSecretKey().getEncoded();
        String encryptedkey = HandshakeCrypto.encrypt(keybyte,key);
        this.putParameter("SessionKey", encryptedkey);

        /* encrypt session iv*/
        byte[] iv = sessionEncrypter.getIvParameterSpec().getIV();
        String encryptediv = HandshakeCrypto.encrypt(iv,key);
        this.putParameter("SessionIV", encryptediv);

        /*put in sessionHost and sessionPort*/
        this.putParameter("ServerHost", SessionHost);
        this.putParameter("ServerPort", String.valueOf(SessionPort));
    }

    public byte[] decryptKey(Key key)
            throws IllegalBlockSizeException,
            InvalidKeyException, BadPaddingException,
            NoSuchAlgorithmException, NoSuchPaddingException {
        byte[] keybyte = HandshakeCrypto.decrypt(this.getParameter("SessionKey"),key);
        return keybyte;
    }

    public byte[] decryptIv(Key key) throws IllegalBlockSizeException, InvalidKeyException, BadPaddingException, NoSuchAlgorithmException, NoSuchPaddingException {
        byte[] ivbyte = HandshakeCrypto.decrypt(this.getParameter("SessionIV"),key);
        return ivbyte;
    }
}
