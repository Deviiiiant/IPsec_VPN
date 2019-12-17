package SessionCrypto;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.io.InputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

public class SessionDecrypter {

    private SessionKey sessionKey;
    private Cipher cipher;
    private IvParameterSpec ivParameterSpec;

    /**
     * generate the sessionKey and cipher used to decrypt
     * @param key
     * @param iv
     * @throws NoSuchPaddingException
     * @throws NoSuchAlgorithmException
     * @throws InvalidAlgorithmParameterException
     * @throws InvalidKeyException
     */
    public SessionDecrypter(String key, String iv)
            throws NoSuchPaddingException, NoSuchAlgorithmException,
            InvalidAlgorithmParameterException, InvalidKeyException {

        //get the sessionKey from the String;
        sessionKey = new SessionKey(key);
        SecretKey secretKey = sessionKey.getSecretKey();

        //read the string and generate the IV;
        Base64.Decoder decoder = Base64.getDecoder();
        byte [] iV = decoder.decode(iv);
        ivParameterSpec = new IvParameterSpec(iV);

        //initialize the cipher based on the secretKey and IV;
        cipher = Cipher.getInstance("AES/CTR/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE,secretKey,ivParameterSpec);
    }

    public SessionDecrypter (byte[] key, byte[] iv) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException {
        sessionKey = new SessionKey(key);
        cipher = Cipher.getInstance("AES/CTR/NoPadding");
        ivParameterSpec = new IvParameterSpec(iv);
        cipher.init(Cipher.DECRYPT_MODE,sessionKey.getSecretKey(),ivParameterSpec);
    }

    /**
     * return the cipherInputStream;
     * @param inputStream
     * @return
     */

    public CipherInputStream openCipherInputStream(InputStream inputStream){
        CipherInputStream cipherInputStream = new CipherInputStream(inputStream,cipher);
        return  cipherInputStream;
    }
}
