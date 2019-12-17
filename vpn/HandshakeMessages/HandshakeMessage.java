package HandshakeMessages;/*
 * Handshake message encoding/decoding and transmission
 * for IK2206 project.
 *
 */

import java.io.IOException;
import java.io.ByteArrayOutputStream;
import java.io.ByteArrayInputStream;

import java.nio.charset.StandardCharsets;
import java.net.InetAddress;
import java.net.Socket;
import java.util.Properties;

/*
 * A Handshake message is represented as a set of parameters -- <key, value> pairs.
 * Extends Properties class.
 */

public class HandshakeMessage extends Properties {
    
    public String getParameter(String param) {
        return this.getProperty(param);
    }

    public void putParameter(String param, String value) {
        this.put(param, value);
    }

    public void send(Socket socket) throws IOException {
        ByteArrayOutputStream byteOutputStream = new ByteArrayOutputStream();
        String comment = "From " + InetAddress.getLocalHost() + ":" + socket.getLocalPort() +
            " to " + socket.getInetAddress().getHostAddress() + ":" + socket.getPort();
        this.storeToXML(byteOutputStream, comment);
        byte[] bytes = byteOutputStream.toByteArray();
        socket.getOutputStream().write(String.format("%d ", bytes.length).getBytes(StandardCharsets.UTF_8));        
        socket.getOutputStream().write(bytes);
        socket.getOutputStream().flush();
        
    }

    public void recv(Socket socket) throws IOException {
        int length = 0;
        for (int n = socket.getInputStream().read(); !Character.isWhitespace(n); n = socket.getInputStream().read()) {
            length = length*10 + Character.getNumericValue(n);
        }
        byte[] data = new byte[length];
        int nread = 0;
        while (nread < length) {
            nread += socket.getInputStream().read(data, nread, length-nread);
        }
        this.loadFromXML(new ByteArrayInputStream(data));
    }


}
