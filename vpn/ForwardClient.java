/**
 * this is forwarder client program
 * adapted for Internet Security and Privacy(IK2206) at KTH
 * based on TCP forwarder client by Peter Sjodin
 */

/**
 * Port forwarding client. Forward data
 * between two TCP ports. Based on Nakov TCP Socket Forward Server 
 * and adapted for IK2206.
 *
 * Original copyright notice below.
 * (c) 2018 Peter Sjodin, KTH
 */

/**
 * Nakov TCP Socket Forward Server - freeware
 * Version 1.0 - March, 2002
 * (c) 2001 by Svetlin Nakov - http://www.nakov.com
 */
 
import HandshakeHelper.CrtTransfer;
import HandshakeHelper.HandshakeCrypto;
import HandshakeHelper.HandshakeVerify;
import HandshakeMessages.ClientHello;
import HandshakeMessages.Forward;
import HandshakeMessages.ServerHello;
import HandshakeMessages.Session;
import SessionCrypto.SessionDecrypter;
import SessionCrypto.SessionEncrypter;
import portforwarder.Arguments;
import portforwarder.ForwardServerClientThread;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.lang.IllegalArgumentException;
import java.lang.Integer;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.io.IOException;

 
public class ForwardClient
{
    private static final boolean ENABLE_LOGGING = true;
    public static final int DEFAULTSERVERPORT = 2206;
    public static final String DEFAULTSERVERHOST = "localhost";
    public static final String PROGRAMNAME = "ForwardClient";

    private static Arguments arguments;
    private static int serverPort;
    private static String serverHost;
    private static SessionEncrypter sessionEncrypter;
    private static SessionDecrypter sessionDecrypter;

    private static void doHandshake() throws CertificateException, InvalidKeyException, BadPaddingException, NoSuchAlgorithmException, IllegalBlockSizeException, NoSuchPaddingException, IOException, InvalidKeySpecException, InvalidAlgorithmParameterException {

        /* Connect to forward server server */
        System.out.println("Connect to " +  arguments.get("handshakehost") + ":" + Integer.parseInt(arguments.get("handshakeport")));
        Socket socket = new Socket(arguments.get("handshakehost"), Integer.parseInt(arguments.get("handshakeport")));

        /* prepare for handshake encryption*/
        PrivateKey privateKey = HandshakeCrypto.getPrivateKeyFromKeyFile(arguments.get("key"));

        /* clientHello */
        ClientHello clientHello = new ClientHello();
        clientHello.putCrtIn(arguments.get("usercert"));
        clientHello.send(socket);
        System.out.println(" hello! this is client ");

        /*receive and verify server hello*/
        ServerHello serverHello = new ServerHello();
        serverHello.recv(socket);
        try{
            HandshakeVerify.verifyCrtString(serverHello.getParameter("Certificate"),
                    CrtTransfer.getCertificateFromFile(arguments.get("cacert")));
            System.out.println("successfully authenticate server");
        }catch (SignatureException | NoSuchProviderException | NoSuchAlgorithmException | InvalidKeyException se){
            System.out.println("fail to authenticate");
            socket.close();
        }



        /*forward message*/
        Forward forward = new Forward();
        
        //forward.encryptContent(publicKey,arguments.get("targethost"),arguments.get("targetport"));
        forward.putParameter("TargetHost",arguments.get("targethost"));
        forward.putParameter("TargetPort",arguments.get("targetport"));
        forward.send(socket);
        System.out.println("hello! this is forward message");

        /*receive and decrypt session message
         * construct session encrypter and decrypter
         */

        Session session = new Session();
        session.recv(socket);
            sessionEncrypter = new SessionEncrypter(session.decryptKey(privateKey),session.decryptIv(privateKey));
            sessionDecrypter = new SessionDecrypter(session.decryptKey(privateKey),session.decryptIv(privateKey));

        serverHost = session.getParameter("ServerHost");
        serverPort = Integer.parseInt(session.getParameter("ServerPort"));
        System.out.println("I've got everything I need!");


        socket.close();

    }

    /*
     * Let user know that we are waiting
     */
    private static void tellUser(ServerSocket listensocket) throws UnknownHostException {
        System.out.println("Client forwarder to target " + arguments.get("targethost") + ":" + arguments.get("targetport"));
        System.out.println("Waiting for incoming connections at " +
                           InetAddress.getLocalHost().getHostAddress() + ":" + listensocket.getLocalPort());
    }
        
    /*
     * Set up client forwarder.
     * Run handshake negotiation, then set up a listening socket and wait for user.
     * When user has connected, start port forwarder thread.
     */
     public static void startForwardClient() throws
            IOException, CertificateException,
            InvalidKeySpecException, NoSuchAlgorithmException,
            IllegalBlockSizeException, InvalidAlgorithmParameterException,
            BadPaddingException, NoSuchPaddingException, InvalidKeyException {

        doHandshake();

        // Wait for client. Accept one connection.

        ForwardServerClientThread forwardThread;
        ServerSocket listensocket;
        
        /* Create a new socket. This is to where the user should connect.
         * ForwardClient sets up port forwarding between this socket
         * and the ServerHost/ServerPort learned from the handshake */
        listensocket = new ServerSocket();
        /* Let the system pick a port number */
        listensocket.bind(null); 
        /* Tell the user, so the user knows where to connect */ 
        tellUser(listensocket);

        Socket clientSocket = listensocket.accept();
        String clientHostPort = clientSocket.getInetAddress().getHostAddress() + ":" + clientSocket.getPort();
        log("Accepted client from " + clientHostPort);
            
        forwardThread = new ForwardServerClientThread(clientSocket, serverHost, serverPort, sessionEncrypter,sessionDecrypter);
        forwardThread.start();
    }

    /**
     * Prints given log message on the standart output if logging is enabled,
     * otherwise ignores it
     */
    public static void log(String aMessage)
    {
        if (ENABLE_LOGGING)
           System.out.println(aMessage);
    }
 
    static void usage() {
        String indent = "";
        System.err.println(indent + "Usage: " + PROGRAMNAME + " options");
        System.err.println(indent + "Where options are:");
        indent += "    ";
        System.err.println(indent + "--targethost=<hostname>");
        System.err.println(indent + "--targetport=<portnumber>");        
        System.err.println(indent + "--handshakehost=<hostname>");
        System.err.println(indent + "--handshakeport=<portnumber>");        
        System.err.println(indent + "--usercert=<filename>");
        System.err.println(indent + "--cacert=<filename>");
        System.err.println(indent + "--key=<filename>");                
    }
    
    /**
     * Program entry point. Reads arguments and run
     * the forward server
     */
    public static void main(String[] args) throws IOException, CertificateException, InvalidKeySpecException, NoSuchAlgorithmException, NoSuchPaddingException, BadPaddingException, InvalidAlgorithmParameterException, InvalidKeyException, IllegalBlockSizeException {
        try {
            arguments = new Arguments();
            arguments.setDefault("handshakeport", Integer.toString(DEFAULTSERVERPORT));
            arguments.setDefault("handshakehost", DEFAULTSERVERHOST);
            arguments.loadArguments(args);
            if (arguments.get("targetport") == null || arguments.get("targethost") == null) {
                throw new IllegalArgumentException("Target not specified");
            }
        } catch(IllegalArgumentException ex) {
            System.out.println(ex);
            usage();
            System.exit(1);
        }
        startForwardClient();
    }
}
