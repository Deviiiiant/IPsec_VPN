/**
 * this is forwarder server program
 * adapted for Internet Security and Privacy(IK2206) at KTH
 * based on TCP forwarder server by Peter Sjodin
 */

/**
 * Port forwarding server. Forward data
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
import HandshakeHelper.HandshakeVerify;
import HandshakeMessages.ClientHello;
import HandshakeMessages.Forward;
import HandshakeMessages.ServerHello;
import HandshakeMessages.Session;
import SessionCrypto.SessionDecrypter;
import SessionCrypto.SessionEncrypter;
import portforwarder.Arguments;
import portforwarder.ForwardServerClientThread;
import portforwarder.Handshake;
import portforwarder.Logger;
import java.lang.Integer;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.cert.X509Certificate;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.InetSocketAddress;
import java.net.UnknownHostException;
import java.io.IOException;

public class ForwardServer
{


    private static final boolean ENABLE_LOGGING = true;
    public static final int DEFAULTSERVERPORT = 2206;
    public static final String DEFAULTSERVERHOST = "localhost";
    public static final String PROGRAMNAME = "ForwardServer";
    private static Arguments arguments;


    private ServerSocket handshakeSocket;
    
    private ServerSocket listenSocket;
    private String targetHost;
    private int targetPort;

    private  SessionEncrypter sessionEncrypter;
    private  SessionDecrypter sessionDecrypter;

    /**
     * Do handshake negotiation with client to authenticate, learn 
     * target host/port, etc.
     */
    private void doHandshake() throws UnknownHostException, IOException, Exception {

        X509Certificate cacert = CrtTransfer.getCertificateFromFile(arguments.get("cacert"));
        Socket clientSocket = handshakeSocket.accept();
        String clientHostPort = clientSocket.getInetAddress().getHostAddress() + ":" + clientSocket.getPort();
        Logger.log("Incoming handshake connection from " + clientHostPort);

        /* receive and verify client hello */
        ClientHello clientHello = new ClientHello();
        clientHello.recv(clientSocket);
        try {
            HandshakeVerify.verifyCrtString(clientHello.getParameter("Certificate"), cacert);
            System.out.println("sucessfully authenticate client");
        }catch (SignatureException se){
            System.out.println("fail to authenticate");
            clientSocket.close();
        }

        /*prepare for handshake encryption*/
        X509Certificate clientCrt = CrtTransfer.gerCertificateFromString(clientHello.getParameter("Certificate"));
        PublicKey publicKey = clientCrt.getPublicKey();

        /* send server hello message*/
        ServerHello serverHello = new ServerHello();
        serverHello.putCrtIn(arguments.get("usercert"));
        serverHello.send(clientSocket);
        System.out.println("hello! this is server");

        /*receive forward*/
        Forward forward = new Forward();
        forward.recv(clientSocket);
        targetHost = forward.getParameter("TargetHost");
        targetPort = Integer.parseInt(forward.getParameter("TargetPort"));
        System.out.println("I get target!");

        /* construct session key for session message*/
        sessionEncrypter = new SessionEncrypter(128);
        sessionDecrypter = new SessionDecrypter(sessionEncrypter.encodeKey(),sessionEncrypter.encodeIV());

        /*send session */
        Session session = new Session();
        session.encryptContent(sessionEncrypter, publicKey, Handshake.serverHost,Handshake.serverPort);
        session.send(clientSocket);
        System.out.println("send the session!");


        clientSocket.close();

        /* listenSocket is a new socket where the ForwardServer waits for the 
         * client to connect. The ForwardServer creates this socket and communicates
         * the socket's address to the ForwardClient during the handshake, so that the 
         * ForwardClient knows to where it should connect (ServerHost/ServerPort parameters).
         * Here, we use a static address instead (serverHost/serverPort). 
         * (This may give "Address already in use" errors, but that's OK for now.)
         */
        listenSocket = new ServerSocket();
        listenSocket.bind(new InetSocketAddress(Handshake.serverHost, Handshake.serverPort));

        /* The final destination. The ForwardServer sets up port forwarding
         * between the listensocket (ie., ServerHost/ServerPort) and the target.
         */
    }

    /**
     * Starts the forward server - binds on a given port and starts serving
     */

    public void startForwardServer() throws Exception
    {
 
        // Bind server on given TCP port
        int port = Integer.parseInt(arguments.get("handshakeport"));
        try {
            handshakeSocket = new ServerSocket(port);
        } catch (IOException ioe) {
            throw new IOException("Unable to bind to port " + port + ": " + ioe);
        }

        log("Nakov Forward Server started on TCP port " + port);
 
        // Accept client connections and process them until stopped
        while(true) {
            ForwardServerClientThread forwardThread;
            
            doHandshake();

            forwardThread = new ForwardServerClientThread(this.listenSocket, this.targetHost,
                    this.targetPort,this.sessionEncrypter,this.sessionDecrypter);
            forwardThread.start();
        }
    }
 
    /**
     * Prints given log message on the standart output if logging is enabled,
     * otherwise ignores it
     */
    public void log(String aMessage)
    {
        if (ENABLE_LOGGING)
           System.out.println(aMessage);
    }
 
    static void usage() {
        String indent = "";
        System.err.println(indent + "Usage: " + PROGRAMNAME + " options");
        System.err.println(indent + "Where options are:");
        indent += "    ";
        System.err.println(indent + "--handshakehost=<hostname>");
        System.err.println(indent + "--handshakeport=<portnumber>");        
        System.err.println(indent + "--usercert=<filename>");
        System.err.println(indent + "--cacert=<filename>");
        System.err.println(indent + "--key=<filename>");                
    }
    
    /**
     * Program entry point. Reads settings, starts check-alive thread and
     * the forward server
     */
    public static void main(String[] args)
        throws Exception
    {
        arguments = new Arguments();
        arguments.setDefault("handshakeport", Integer.toString(DEFAULTSERVERPORT));
        arguments.setDefault("handshakehost", DEFAULTSERVERHOST);
        arguments.loadArguments(args);
        
        ForwardServer srv = new ForwardServer();
        srv.startForwardServer();
    }
 
}
