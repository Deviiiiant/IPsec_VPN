package portforwarder; /**
 * ForwardServerClientThread handles the clients of Nakov Forward Server. It
 * connects two sockets and starts the TCP forwarding between given client
 * and its assigned server. After the forwarding is failed and the two threads
 * are stopped, closes the sockets.
 *
 */

/**
 * Modifications for IK2206:
 * - Server pool removed
 * - Two variants - client connects to listening socket or client is already connected
 *
 * Peter Sjodin, KTH
 */

import SessionCrypto.SessionDecrypter;
import SessionCrypto.SessionEncrypter;

import java.net.Socket;
import java.net.ServerSocket;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

public class ForwardServerClientThread extends Thread
{
    private Socket mClientSocket = null;
    private Socket mServerSocket = null;
    private ServerSocket mListenSocket = null;
    private boolean mBothConnectionsAreAlive = false;
    private String mClientHostPort;
    private String mServerHostPort;
    private int mServerPort;
    private String mServerHost;
    private SessionEncrypter sessionEncrypter;
    private SessionDecrypter sessionDecrypter;
    private boolean isClient = false;
    private InputStream clientIn;
    private InputStream serverIn;
    private OutputStream clientOut;
    private OutputStream serverOut;

    /**
     * Creates a client thread for handling clients of NakovForwardServer.
     * A client socket should be connected and passed to this constructor.
     * A server socket is created later by run() method.
     */
    public ForwardServerClientThread(Socket aClientSocket, String serverhost, int serverport,SessionEncrypter sessionEncrypter, SessionDecrypter sessionDecrypter)

    {
        mClientSocket = aClientSocket;
        mServerPort = serverport;
        mServerHost = serverhost;
        this.sessionEncrypter = sessionEncrypter;
        this.sessionDecrypter = sessionDecrypter;
        this.isClient = true;

    }
 
    /**
     * Creates a client thread for handling clients of NakovForwardServer.
     * Wait for client to connect on client listening socket.
     * A server socket is created later by run() method.
     */
    public ForwardServerClientThread(ServerSocket listensocket, String serverhost, int serverport,SessionEncrypter sessionEncrypter, SessionDecrypter sessionDecrypter) throws IOException
    {
        mListenSocket = listensocket;
        //mServerHost =  listensocket.getInetAddress().getHostAddress();
        mServerPort = serverport;
        mServerHost = serverhost;
        this.sessionEncrypter = sessionEncrypter;
        this.sessionDecrypter = sessionDecrypter;
    }

    public ServerSocket getListenSocket() {
        return mListenSocket;
    }

    /**
     * Obtains a destination server socket to some of the servers in the list.
     * Starts two threads for forwarding : "client in <--> dest server out" and
     * "dest server in <--> client out", waits until one of these threads stop
     * due to read/write failure or connection closure. Closes opened connections.
     * 
     * If there is a listen socket, first wait for incoming connection
     * on the listen socket.
     */
    public void run()
    {
        try {
 
            // Wait for incoming connection on listen socket, if there is one 
           if (mListenSocket != null) {
               mClientSocket = mListenSocket.accept();
               mClientHostPort = mClientSocket.getInetAddress().getHostAddress() + ":" + mClientSocket.getPort();
               Logger.log("Accepted from  " + mServerPort + " <--> " + mClientHostPort + "  started.");

           }
           else {
               mClientHostPort = mClientSocket.getInetAddress().getHostAddress() + ":" + mClientSocket.getPort();
           }

            mServerSocket = new Socket(mServerHost, mServerPort);

           // Obtain input and output streams of server and client

            if (isClient){
                this.serverIn = sessionDecrypter.openCipherInputStream(mServerSocket.getInputStream());
                this.serverOut = sessionEncrypter.openCipherOutputStream(mServerSocket.getOutputStream());
                this.clientIn = mClientSocket.getInputStream();
                this.clientOut = mClientSocket.getOutputStream();
            }
                else {
                this.clientOut= sessionEncrypter.openCipherOutputStream(mClientSocket.getOutputStream());
                this.clientIn = sessionDecrypter.openCipherInputStream(mClientSocket.getInputStream());
                this.serverIn = mServerSocket.getInputStream();
                this.serverOut = mServerSocket.getOutputStream();
            }

           mServerHostPort = mServerHost + ":" + mServerPort;
           Logger.log("TCP Forwarding  " + mClientHostPort + " <--> " + mServerHostPort + "  started.");
 
           // Start forwarding of socket data between server and client
           ForwardThread clientForward = new ForwardThread(this, clientIn, serverOut);
           ForwardThread serverForward = new ForwardThread(this, serverIn, clientOut);
           mBothConnectionsAreAlive = true;
           clientForward.start();
           serverForward.start();
 
        } catch (IOException ioe) {
           ioe.printStackTrace();
        }
    }
 
    /**
     * connectionBroken() method is called by forwarding child threads to notify
     * this thread (their parent thread) that one of the connections (server or client)
     * is broken (a read/write failure occured). This method disconnects both server
     * and client sockets causing both threads to stop forwarding.
     */
    public synchronized void connectionBroken()
    {
        if (mBothConnectionsAreAlive) {
           // One of the connections is broken. Close the other connection and stop forwarding
           // Closing these socket connections will close their input/output streams
           // and that way will stop the threads that read from these streams
           try { mServerSocket.close(); } catch (IOException e) {}
           try { mClientSocket.close(); } catch (IOException e) {}
 
           mBothConnectionsAreAlive = false;
 
           Logger.log("TCP Forwarding  " + mClientHostPort + " <--> " + mServerHostPort + "  stopped.");
        }
    }
 
}
