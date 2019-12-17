package SessionCrypto;


import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

public class SessionKey  {

    SecretKey secretKey;

    public SessionKey(Integer length) throws NoSuchAlgorithmException {
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(length);
        secretKey = keyGenerator.generateKey();
    }

    public SessionKey(byte[] key){
        secretKey = new SecretKeySpec(key,"AES");
    }

    public SessionKey(String key){
        secretKey = new SecretKeySpec(Base64.getDecoder().decode(key),"AES");
    }


    public SecretKey getSecretKey(){
        return this.secretKey;
    }

    public String getEncodedKey (){
        Base64.Encoder encoder = Base64.getEncoder();
        byte[] keyByte= secretKey.getEncoded();
        String s = encoder.encodeToString(keyByte);
        return s;
    }
}
