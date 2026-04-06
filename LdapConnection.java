import java.io.*;
import java.net.*;

public class LdapConnection {

    private Socket socket;
    private InputStream  in;
    private OutputStream out;
    private String host;
    private int    port;
    private int    messageId = 1; // RFC 4511: messageID must be unique per session

    // ----------------------------------------------------------------
    // CONSTRUCTOR
    // ----------------------------------------------------------------
    public LdapConnection(String host, int port) {
        this.host = host;
        this.port = port;
    }

    // ----------------------------------------------------------------
    // CONNECT TO LDAP SERVER
    // Opens raw TCP socket to port 389
    // ----------------------------------------------------------------
    public void connect() throws IOException {
        System.out.println("Connecting to LDAP server " + host + ":" + port + "...");
        socket = new Socket(host, port);
        in     = socket.getInputStream();
        out    = socket.getOutputStream();
        System.out.println("Connected successfully.");
    }

    // ----------------------------------------------------------------
    // DISCONNECT FROM LDAP SERVER
    // Sends unbind request then closes socket
    // RFC 4511 Section 4.3 — UnbindRequest
    // ----------------------------------------------------------------
    public void disconnect() throws IOException {
        if (socket != null && !socket.isClosed()) {
            System.out.println("Sending unbind request...");
            byte[] unbindRequest = BerEncoder.buildUnbindRequest(nextMessageId());
            sendPacket(unbindRequest);
            socket.close();
            System.out.println("Disconnected.");
        }
    }

    // ----------------------------------------------------------------
    // BIND — authenticate to the LDAP server
    // RFC 4511 Section 4.2
    // Returns true if bind was successful
    // ----------------------------------------------------------------
    public boolean bind(String bindDN, String password) throws IOException {
        int msgId = nextMessageId();

        System.out.println("Sending bind request (DN: " +
            (bindDN.isEmpty() ? "anonymous" : bindDN) + ")...");

        byte[] bindRequest = BerEncoder.buildBindRequest(msgId, bindDN, password);

        System.out.println("DEBUG: Bind request bytes: " +
            BerEncoder.toHex(bindRequest));

        sendPacket(bindRequest);

        // Read and decode response
        byte[] response = readPacket();
        System.out.println("DEBUG: Bind response bytes: " +
            BerEncoder.toHex(response));

        BerDecoder.LdapResponse decoded = BerDecoder.decode(response);
        BerDecoder.printResponse(decoded);

        if (decoded.isBindResponse() && decoded.isSuccess()) {
            System.out.println("Bind successful.");
            return true;
        } else {
            System.out.println("Bind failed: " +
                BerDecoder.getResultCodeMeaning(decoded.resultCode));
            return false;
        }
    }

    // ----------------------------------------------------------------
    // ANONYMOUS BIND
    // Binds with empty DN and empty password
    // RFC 4511 Section 4.2 — simple authentication with empty credentials
    // ----------------------------------------------------------------
    public boolean anonymousBind() throws IOException {
        int msgId = nextMessageId();

        System.out.println("Sending anonymous bind request...");

        byte[] bindRequest = BerEncoder.buildAnonymousBindRequest(msgId);

        System.out.println("DEBUG: Anonymous bind request bytes: " +
            BerEncoder.toHex(bindRequest));

        sendPacket(bindRequest);

        byte[] response = readPacket();
        System.out.println("DEBUG: Bind response bytes: " +
            BerEncoder.toHex(response));

        BerDecoder.LdapResponse decoded = BerDecoder.decode(response);
        BerDecoder.printResponse(decoded);

        return decoded.isBindResponse() && decoded.isSuccess();
    }

    // ----------------------------------------------------------------
    // SEARCH — query the LDAP directory
    // RFC 4511 Section 4.5
    // Returns list of matching entries
    // ----------------------------------------------------------------
    public java.util.List<BerDecoder.LdapEntry> search(
            String baseDN,
            String searchAttribute,
            String searchValue) throws IOException {

        int msgId = nextMessageId();

        System.out.println("Sending search request...");
        System.out.println("  Base DN   : " + baseDN);
        System.out.println("  Filter    : (" + searchAttribute +
                           "=" + searchValue + ")");

        byte[] searchRequest = BerEncoder.buildSearchRequest(
            msgId, baseDN, searchAttribute, searchValue);

        System.out.println("DEBUG: Search request bytes: " +
            BerEncoder.toHex(searchRequest));

        sendPacket(searchRequest);

        // Collect all responses until SearchResultDone
        // RFC 4511: server sends zero or more SearchResultEntry
        // followed by exactly one SearchResultDone
        java.util.List<BerDecoder.LdapEntry> entries = new java.util.ArrayList<>();

        while (true) {
            byte[] responseBytes = readPacket();
            System.out.println("DEBUG: Response bytes: " +
                BerEncoder.toHex(responseBytes));

            BerDecoder.LdapResponse response = BerDecoder.decode(responseBytes);
            BerDecoder.printResponse(response);

            if (response.isSearchEntry()) {
                // Add all entries from this response
                entries.addAll(response.entries);
            } else if (response.isSearchDone()) {
                // Search is complete
                if (!response.isSuccess() && response.resultCode != 0) {
                    System.out.println("Search completed with result: " +
                        BerDecoder.getResultCodeMeaning(response.resultCode));
                }
                break;
            } else {
                // Unexpected response — log and break
                System.out.println("Unexpected response tag: " +
                    String.format("0x%02X", response.responseTag));
                break;
            }
        }

        return entries;
    }

    // ----------------------------------------------------------------
    // SEND A PACKET TO THE LDAP SERVER
    // Writes raw bytes to the socket output stream
    // ----------------------------------------------------------------
    private void sendPacket(byte[] packet) throws IOException {
        out.write(packet);
        out.flush();
    }

    // ----------------------------------------------------------------
    // READ A COMPLETE LDAP PACKET FROM THE SERVER
    // RFC 4511: each message is a BER SEQUENCE
    // We read the tag, then the length, then the value bytes
    // ----------------------------------------------------------------
    private byte[] readPacket() throws IOException {
        // Read tag byte (should be 0x30 for SEQUENCE)
        int tag = in.read();
        if (tag == -1) throw new IOException("Connection closed by server");

        // Read length (may be multi-byte)
        int firstLenByte = in.read() & 0xFF;
        int contentLength;

        if (firstLenByte < 128) {
            // Short form length
            contentLength = firstLenByte;
        } else {
            // Long form length
            int numBytes = firstLenByte & 0x7F;
            contentLength = 0;
            for (int i = 0; i < numBytes; i++) {
                contentLength = (contentLength << 8) | (in.read() & 0xFF);
            }
        }

        // Read the content bytes
        byte[] content = new byte[contentLength];
        int bytesRead = 0;
        while (bytesRead < contentLength) {
            int r = in.read(content, bytesRead, contentLength - bytesRead);
            if (r == -1) throw new IOException("Connection closed mid-packet");
            bytesRead += r;
        }

        // Reconstruct the full packet including tag and length
        // We need the full packet for decoding
        byte[] lengthBytes = BerEncoder.encodeLength(contentLength);
        byte[] fullPacket  = new byte[1 + lengthBytes.length + contentLength];
        fullPacket[0]      = (byte) tag;
        System.arraycopy(lengthBytes, 0, fullPacket, 1, lengthBytes.length);
        System.arraycopy(content, 0, fullPacket,
            1 + lengthBytes.length, contentLength);

        return fullPacket;
    }

    // ----------------------------------------------------------------
    // MESSAGE ID COUNTER
    // RFC 4511 Section 4.1.1.1 — messageID must be non-zero
    // and unique within a session
    // ----------------------------------------------------------------
    private int nextMessageId() {
        return messageId++;
    }

    // ----------------------------------------------------------------
    // GETTERS
    // ----------------------------------------------------------------
    public boolean isConnected() {
        return socket != null && !socket.isClosed() && socket.isConnected();
    }

    public String getHost() { return host; }
    public int    getPort() { return port; }
}