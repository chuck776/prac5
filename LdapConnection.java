import java.io.*;
import java.net.*;
import java.util.List;
import java.util.ArrayList;
// This class manages the LDAP connection and implements core operations like bind, search, add, delete, and modify.
public class LdapConnection {

    private Socket socket;
    private InputStream  in;
    private OutputStream out;
    private String host;
    private int    port;
    private int    messageId = 1; // RFC 4511: messageID must be non-zero and unique per session

    // ----------------------------------------------------------------
    // CONSTRUCTOR
    // initializes host and port but does not connect yet
    // ----------------------------------------------------------------
    public LdapConnection(String host, int port) {
        this.host = host;
        this.port = port;
    }

    // ----------------------------------------------------------------
    // CONNECT
    // simply opens a TCP socket to the LDAP server and initializes input/output streams
    // ----------------------------------------------------------------
    public void connect() throws IOException {
        System.out.println("Connecting to LDAP server " + host + ":" + port + "...");
        socket = new Socket(host, port);
        in     = socket.getInputStream();
        out    = socket.getOutputStream();
        System.out.println("Connected successfully.");
    }

    // ----------------------------------------------------------------
    // DISCONNECT — sends UnbindRequest then closes socket
    // RFC 4511 Section 4.3
    // RFC 4511: "The client initiates the unbind operation by sending an UnbindRequest to the server. 
    // The server does not send a response to an UnbindRequest. The client closes
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
    // BIND (RFC 4511 Section 4.2)
    // This sends a simple bind request with the provided DN and password.
    // ----------------------------------------------------------------
    public boolean bind(String bindDN, String password) throws IOException {
        int msgId = nextMessageId();

        System.out.println("Sending bind request (DN: " +
            (bindDN.isEmpty() ? "anonymous" : bindDN) + ")...");

        byte[] bindRequest = BerEncoder.buildBindRequest(msgId, bindDN, password);
        System.out.println("DEBUG: Bind request bytes: " + BerEncoder.toHex(bindRequest));
        sendPacket(bindRequest);

        byte[] response = readPacket();
        System.out.println("DEBUG: Bind response bytes: " + BerEncoder.toHex(response));

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

    public boolean anonymousBind() throws IOException {
        int msgId = nextMessageId();
        System.out.println("Sending anonymous bind request...");
        byte[] bindRequest = BerEncoder.buildAnonymousBindRequest(msgId);
        System.out.println("DEBUG: Anonymous bind request bytes: " + BerEncoder.toHex(bindRequest));
        sendPacket(bindRequest);
        byte[] response = readPacket();
        System.out.println("DEBUG: Bind response bytes: " + BerEncoder.toHex(response));
        BerDecoder.LdapResponse decoded = BerDecoder.decode(response);
        BerDecoder.printResponse(decoded);
        return decoded.isBindResponse() && decoded.isSuccess();
    }

    // ----------------------------------------------------------------
    // SEARCH — equality match filter (RFC 4511 Section 4.5)
    // searches for entries under baseDN where searchAttribute equals searchValue
    // ----------------------------------------------------------------
    public List<BerDecoder.LdapEntry> search(String baseDN,
                                              String searchAttribute,
                                              String searchValue) throws IOException {
        int msgId = nextMessageId();

        System.out.println("Sending search request...");
        System.out.println("  Base DN   : " + baseDN);
        System.out.println("  Filter    : (" + searchAttribute + "=" + searchValue + ")");

        byte[] searchRequest = BerEncoder.buildSearchRequest(
            msgId, baseDN, searchAttribute, searchValue);
        System.out.println("DEBUG: Search request bytes: " + BerEncoder.toHex(searchRequest));
        sendPacket(searchRequest);

        return collectSearchResults();
    }

    // ----------------------------------------------------------------
    // SEARCH — greaterOrEqual filter (RFC 4511 Section 4.5.1)
    // Used for server-side speed >= threshold queries.
    // The LDAP greaterOrEqual filter does a lexicographic comparison
    // on the stored string values, so speeds must be zero-padded to
    // the same width (e.g. "300") for correct numeric ordering, OR
    // we accept that the server handles numeric ordering via the
    // INTEGER syntax on the 'description' attribute.
    // For OpenLDAP with 'description' as caseIgnoreString, the
    // comparison is lexicographic — we document this for the demo.
    // ----------------------------------------------------------------
    public List<BerDecoder.LdapEntry> searchGreaterOrEqual(String baseDN,
                                                            String attribute,
                                                            String value) throws IOException {
        int msgId = nextMessageId();

        System.out.println("Sending greaterOrEqual search request...");
        System.out.println("  Base DN   : " + baseDN);
        System.out.println("  Filter    : (" + attribute + ">=" + value + ")");

        byte[] searchRequest = BerEncoder.buildSearchRequestGreaterOrEqual(
            msgId, baseDN, attribute, value);
        System.out.println("DEBUG: Search request bytes: " + BerEncoder.toHex(searchRequest));
        sendPacket(searchRequest);

        return collectSearchResults();
    }

    // ----------------------------------------------------------------
    // ADD — creates a new LDAP entry (RFC 4511 Section 4.7)
    // attributes: each String[] is { attrName, val1, val2, ... }
    //this method takes the entry DN and a 2D array of attributes, where each inner array contains the attribute name followed by its values. This allows us to add entries with multiple attributes and multiple values per attribute.
    // ----------------------------------------------------------------
    public boolean add(String entryDN, String[][] attributes) throws IOException {
        int msgId = nextMessageId();

        System.out.println("Sending add request for DN: " + entryDN);
        byte[] addRequest = BerEncoder.buildAddRequest(msgId, entryDN, attributes);
        System.out.println("DEBUG: Add request bytes: " + BerEncoder.toHex(addRequest));
        sendPacket(addRequest);

        byte[] responseBytes = readPacket();
        System.out.println("DEBUG: Add response bytes: " + BerEncoder.toHex(responseBytes));

        BerDecoder.LdapResponse response = BerDecoder.decode(responseBytes);
        BerDecoder.printResponse(response);

        if (response.isAddResponse() && response.isSuccess()) {
            System.out.println("Add successful.");
            return true;
        } else {
            System.out.println("Add failed: " +
                BerDecoder.getResultCodeMeaning(response.resultCode) +
                (response.errorMessage.isEmpty() ? "" : " — " + response.errorMessage));
            return false;
        }
    }

    // ----------------------------------------------------------------
    // DELETE — removes an LDAP entry (RFC 4511 Section 4.8)
    //this only takes the entry DN since delete doesn't need attribute values
    // ----------------------------------------------------------------
    public boolean delete(String entryDN) throws IOException {
        int msgId = nextMessageId();

        System.out.println("Sending delete request for DN: " + entryDN);
        byte[] delRequest = BerEncoder.buildDeleteRequest(msgId, entryDN);
        System.out.println("DEBUG: Delete request bytes: " + BerEncoder.toHex(delRequest));
        sendPacket(delRequest);

        byte[] responseBytes = readPacket();
        System.out.println("DEBUG: Delete response bytes: " + BerEncoder.toHex(responseBytes));

        BerDecoder.LdapResponse response = BerDecoder.decode(responseBytes);
        BerDecoder.printResponse(response);

        if (response.isDeleteResponse() && response.isSuccess()) {
            System.out.println("Delete successful.");
            return true;
        } else {
            System.out.println("Delete failed: " +
                BerDecoder.getResultCodeMeaning(response.resultCode) +
                (response.errorMessage.isEmpty() ? "" : " — " + response.errorMessage));
            return false;
        }
    }

    // ----------------------------------------------------------------
    // MODIFY — replaces an attribute value on an existing entry
    // (RFC 4511 Section 4.6)
    // operation: 0=add, 1=delete, 2=replace
    // Uses MODIFY_OP_REPLACE so the new value overwrites the old one.
    // ----------------------------------------------------------------
    public boolean modify(String entryDN,
                          int operation,
                          String attrName,
                          String[] values) throws IOException {
        int msgId = nextMessageId();

        System.out.println("Sending modify request for DN: " + entryDN);
        System.out.println("  Operation : " + operationName(operation));
        System.out.println("  Attribute : " + attrName);

        byte[] modRequest = BerEncoder.buildModifyRequest(
            msgId, entryDN, operation, attrName, values);
        System.out.println("DEBUG: Modify request bytes: " + BerEncoder.toHex(modRequest));
        sendPacket(modRequest);

        byte[] responseBytes = readPacket();
        System.out.println("DEBUG: Modify response bytes: " + BerEncoder.toHex(responseBytes));

        BerDecoder.LdapResponse response = BerDecoder.decode(responseBytes);
        BerDecoder.printResponse(response);

        if (response.isModifyResponse() && response.isSuccess()) {
            System.out.println("Modify successful.");
            return true;
        } else {
            System.out.println("Modify failed: " +
                BerDecoder.getResultCodeMeaning(response.resultCode) +
                (response.errorMessage.isEmpty() ? "" : " — " + response.errorMessage));
            return false;
        }
    }

    // ----------------------------------------------------------------
    // COLLECT SEARCH RESULTS
    // Reads packets until SearchResultDone (RFC 4511 Section 4.5.2)
    // collects SearchResultEntry responses into a list and returns it.
    // ----------------------------------------------------------------
    private List<BerDecoder.LdapEntry> collectSearchResults() throws IOException {
        List<BerDecoder.LdapEntry> entries = new ArrayList<>();

        while (true) {
            byte[] responseBytes = readPacket();
            System.out.println("DEBUG: Response bytes: " + BerEncoder.toHex(responseBytes));

            BerDecoder.LdapResponse response = BerDecoder.decode(responseBytes);
            BerDecoder.printResponse(response);

            if (response.isSearchEntry()) {
                entries.addAll(response.entries);
            } else if (response.isSearchDone()) {
                if (!response.isSuccess() && response.resultCode != 0) {
                    System.out.println("Search completed with result: " +
                        BerDecoder.getResultCodeMeaning(response.resultCode));
                }
                break;
            } else {
                System.out.println("Unexpected response tag: " +
                    String.format("0x%02X", response.responseTag));
                break;
            }
        }

        return entries;
    }

    // ----------------------------------------------------------------
    // SEND PACKET
    // This sends the full LDAP message bytes to the server. 
    // The caller is responsible
    // ----------------------------------------------------------------
    private void sendPacket(byte[] packet) throws IOException {
        out.write(packet);
        out.flush();
    }

    // ----------------------------------------------------------------
    // READ A COMPLETE LDAP PACKET
    // RFC 4511: each message is a BER SEQUENCE read tag, length, value
    // this handles both short and long form lengths and ensures we read the full content
    // ----------------------------------------------------------------
    private byte[] readPacket() throws IOException {
        int tag = in.read();
        if (tag == -1) throw new IOException("Connection closed by server");

        int firstLenByte = in.read() & 0xFF;
        int contentLength;

        if (firstLenByte < 128) {
            contentLength = firstLenByte;
        } else {
            int numBytes = firstLenByte & 0x7F;
            contentLength = 0;
            for (int i = 0; i < numBytes; i++) {
                contentLength = (contentLength << 8) | (in.read() & 0xFF);
            }
        }

        byte[] content = new byte[contentLength];
        int bytesRead = 0;
        while (bytesRead < contentLength) {
            int r = in.read(content, bytesRead, contentLength - bytesRead);
            if (r == -1) throw new IOException("Connection closed mid-packet");
            bytesRead += r;
        }

        byte[] lengthBytes = BerEncoder.encodeLength(contentLength);
        byte[] fullPacket  = new byte[1 + lengthBytes.length + contentLength];
        fullPacket[0]      = (byte) tag;
        System.arraycopy(lengthBytes, 0, fullPacket, 1, lengthBytes.length);
        System.arraycopy(content, 0, fullPacket, 1 + lengthBytes.length, contentLength);

        return fullPacket;
    }

    // ----------------------------------------------------------------
    // HELPERS
    // these are not part of the core LDAP protocol but help with message IDs and logging
    // ----------------------------------------------------------------
    private int nextMessageId() { return messageId++; }

    private String operationName(int op) {
        switch (op) {
            case BerEncoder.MODIFY_OP_ADD:     return "add";
            case BerEncoder.MODIFY_OP_DELETE:  return "delete";
            case BerEncoder.MODIFY_OP_REPLACE: return "replace";
            default: return "unknown(" + op + ")";
        }
    }

    public boolean isConnected() {
        return socket != null && !socket.isClosed() && socket.isConnected();
    }

    public String getHost() { return host; }
    public int    getPort() { return port; }
}