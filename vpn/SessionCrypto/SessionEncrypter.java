package SessionCrypto;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import java.io.OutputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;

public class SessionEncrypter {

    // instance field;
    Cipher cipher;
    SessionKey sessionKey;
    IvParameterSpec ivParameterSpec;



    /**
     * generate and initialize the cipher;
     * @param keyLength
     * @throws NoSuchAlgorithmException
     * @throws NoSuchPaddingException
     * @throws InvalidAlgorithmParameterException
     * @throws InvalidKeyException
     */
    public SessionEncrypter(Integer keyLength) throws NoSuchAlgorithmException,
            NoSuchPaddingException, InvalidAlgorithmParameterException,
            InvalidKeyException {

        //generate the sessionKey comforming to the keyLength;
        sessionKey = new SessionKey(keyLength);
        SecretKey secretKey = sessionKey.getSecretKey();

        //generate the IV and IvparameterSpec
        SecureRandom secureRandom = new SecureRandom();
        byte[] iv = new byte[keyLength/8];
        secureRandom.nextBytes(iv);
        ivParameterSpec = new IvParameterSpec(iv);

        //initialize the cipher;
        cipher = Cipher.getInstance("AES/CTR/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE,secretKey,ivParameterSpec);
    }

    public SessionEncrypter(byte[] key, byte[] iv) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException {
        sessionKey = new SessionKey(key);
        cipher = Cipher.getInstance("AES/CTR/NoPadding");
        ivParameterSpec = new IvParameterSpec(iv);
        cipher.init(Cipher.ENCRYPT_MODE,sessionKey.getSecretKey(),ivParameterSpec);
    }


    /**
     * return the encodedKey
     * @return
     */
    public String encodeKey(){
        return sessionKey.getEncodedKey();
    }


    /**
     * return the encodedIv
     * @return
     */
    public String encodeIV(){
        Base64.Encoder encoder = Base64.getEncoder();
        byte[] iv = ivParameterSpec.getIV();
        return encoder.encodeToString(iv);
    }

    /**
     * return the cipherOutputStream;
     * @param outputStream
     * @return
     */
    public CipherOutputStream openCipherOutputStream(OutputStream outputStream){
        CipherOutputStream cipherOutputStream = new CipherOutputStream(outputStream,cipher);
        return  cipherOutputStream;
    }

    public SessionKey getSessionKey(){
        return this.sessionKey;
    }
    public IvParameterSpec getIvParameterSpec(){
        return this.ivParameterSpec;
    }
}
