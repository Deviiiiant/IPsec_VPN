# port forwarding VPN

This VPN tool  is the assignment at Internet Security and Privacy (IK2206), which can be found at KTH website: https://www.kth.se/student/kurser/kurs/IK2206?l=en. 

This implementation includes forwarder client, server, certificates, private key as examples. 

Following will explain how this "protocol" works. 

#### 1. forwarder server starts working and keep listening on the handshake port;
#### 2. forwarder client starts working and send message to server handshake port;
#### 3. Handshake phase:
  1. forwarder client send his certificate to forwarder server (client hello) ;
  2. forwarder server receive client's certificate and verify if it is signed by certificate authority. If not, the server report "fail to verify certificate" error and close the socket. If verifying successfully, the server will send his certificate to client (server hello); 
  3. client recieve server hello message and verify server's certificate. If verification is successful, client will send the target host and target port (forward message) to the forwarder server but without encryption (it would be a weakness!); 
  4. after receiving the forward message, the server send session port through which the server forward the message from client to the target socket, session key and key IV which are encrypted by client's public key. However, the session port is not encrypted;
  5. client recieve the session message and construct session encrypter and decrypter, after which the client will close the hanshake phase and tell user his open session port;

#### 4. user send message to forwarder client instead of sending message directly to target host, the client will encrypt the message used session key and send it to forwarder server; 
#### 5. server recieve the cipher text and decrypt it, forward it to target host. vice and versa. 

### encryption detail:
  1. the key used in handshake phase is public key, it means the client and server are supposed to make an agreement on the same CA. The public key is generated using RSA alogrithm and it is 2048 bit-long;
  2. the session encryption use symmetric key and operate at CTR mode;
  
  ### security issue: 
   1. due to the certificate verification only check the if the certificate is signed by CA, it is vulnerable to middle-man attack. the attakc would exploit this weakness, use the ceritficate signed by CA to fool the client and server, and steal the session key, therefore the sequent session is totally transparent to him;
   2. the entire forward message and a half of session message are not encrypted. so these port are transparent. I am not sure if that would be an issue, but I think it would be better to encrypt these messages;
   
