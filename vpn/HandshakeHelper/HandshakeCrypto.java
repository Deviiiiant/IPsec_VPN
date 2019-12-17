package HandshakeHelper;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;

public class HandshakeCrypto {


    // encrypt byte array to String
    public static String encrypt(byte[] plaintext, Key key)
            throws NoSuchPaddingException, NoSuchAlgorithmException,
            InvalidKeyException, BadPaddingException, IllegalBlockSizeException {

        Cipher c = Cipher.getInstance("RSA");
        c.init(Cipher.ENCRYPT_MODE,key);
        byte[] ciphertext = c.doFinal(plaintext);
        return Base64.getEncoder().encodeToString(ciphertext);

    }


    // decrypting....
    public static byte[] decrypt(String cipherText, Key key)
            throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException,
            BadPaddingException, IllegalBlockSizeException {

        Cipher c = Cipher.getInstance("RSA");
        c.init(Cipher.DECRYPT_MODE,key);
        byte[] ciphertextbytes = Base64.getDecoder().decode(cipherText);
        return c.doFinal(ciphertextbytes);

    }

    //get public key from key certificate....
    public static PublicKey getPublicKeyFromCertFile(String certfile)
            throws FileNotFoundException, CertificateException {

        //get the certificate from .pem file;
        FileInputStream fi = new FileInputStream(certfile);
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        X509Certificate cert = (X509Certificate) cf.generateCertificate(fi);
        return cert.getPublicKey();

    }

    //get private key from file....
    public static PrivateKey getPrivateKeyFromKeyFile(String keyFile)
            throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {

        Path path = Paths.get(keyFile);
        byte[] privateKeyByte = Files.readAllBytes(path);
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(privateKeyByte);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return keyFactory.generatePrivate(spec);

    }


}
