import java.util.ArrayList;
import java.util.List;

public class BerDecoder {

    // ----------------------------------------------------------------
    // RESULT CODE MEANINGS (RFC 4511 Section 4.1.9)
    // ----------------------------------------------------------------
    public static String getResultCodeMeaning(int code) {
        switch (code) {
            case 0:  return "success";
            case 1:  return "operationsError";
            case 2:  return "protocolError";
            case 3:  return "timeLimitExceeded";
            case 4:  return "sizeLimitExceeded";
            case 7:  return "authMethodNotSupported";
            case 8:  return "strongerAuthRequired";
            case 10: return "referral";
            case 11: return "adminLimitExceeded";
            case 16: return "noSuchAttribute";
            case 17: return "undefinedAttributeType";
            case 20: return "attributeOrValueExists";
            case 21: return "invalidAttributeSyntax";
            case 32: return "noSuchObject";
            case 33: return "aliasDereferencingProblem";
            case 34: return "invalidDNSyntax";
            case 48: return "inappropriateAuthentication";
            case 49: return "invalidCredentials";
            case 50: return "insufficientAccessRights";
            case 51: return "busy";
            case 52: return "unavailable";
            case 53: return "unwillingToPerform";
            case 64: return "namingViolation";
            case 65: return "objectClassViolation";
            case 66: return "notAllowedOnNonLeaf";
            case 67: return "notAllowedOnRDN";
            case 68: return "entryAlreadyExists";
            case 80: return "other";
            default: return "unknown(" + code + ")";
        }
    }

    // ----------------------------------------------------------------
    // PARSED ATTRIBUTE — holds one attribute name and its values
    // ----------------------------------------------------------------
    public static class LdapAttribute {
        public String name;
        public List<String> values = new ArrayList<>();

        public LdapAttribute(String name) {
            this.name = name;
        }

        @Override
        public String toString() {
            return name + ": " + values;
        }
    }

    // ----------------------------------------------------------------
    // PARSED ENTRY — holds a DN and its attributes
    // ----------------------------------------------------------------
    public static class LdapEntry {
        public String dn;
        public List<LdapAttribute> attributes = new ArrayList<>();

        public LdapEntry(String dn) {
            this.dn = dn;
        }

        // Find a specific attribute by name (case insensitive)
        public String getAttributeValue(String attrName) {
            for (LdapAttribute attr : attributes) {
                if (attr.name.equalsIgnoreCase(attrName)) {
                    if (!attr.values.isEmpty()) {
                        return attr.values.get(0);
                    }
                }
            }
            return null;
        }

        @Override
        public String toString() {
            StringBuilder sb = new StringBuilder();
            sb.append("DN: " + dn + "\n");
            for (LdapAttribute attr : attributes) {
                for (String val : attr.values) {
                    sb.append("  " + attr.name + ": " + val + "\n");
                }
            }
            return sb.toString();
        }
    }

    // ----------------------------------------------------------------
    // PARSED LDAP RESPONSE — holds the full decoded response
    // ----------------------------------------------------------------
    public static class LdapResponse {
        public int messageId;
        public int responseTag;
        public int resultCode      = -1;
        public String matchedDN    = "";
        public String errorMessage = "";
        public List<LdapEntry> entries = new ArrayList<>();

        public boolean isSuccess() {
            return resultCode == 0;
        }

        public boolean isSearchEntry() {
            return responseTag == BerEncoder.TAG_SEARCH_ENTRY;
        }

        public boolean isSearchDone() {
            return responseTag == BerEncoder.TAG_SEARCH_DONE;
        }

        public boolean isBindResponse() {
            return responseTag == BerEncoder.TAG_BIND_RESPONSE;
        }
    }

    // ----------------------------------------------------------------
    // READ LENGTH FROM BER ENCODED BYTES
    // Returns the length value
    // Updates pos[] array (used as a mutable integer reference)
    // ----------------------------------------------------------------
    public static int readLength(byte[] data, int[] pos) {
        int firstByte = data[pos[0]++] & 0xFF;

        if (firstByte < 128) {
            // Short form — length is directly the byte value
            return firstByte;
        } else {
            // Long form — first byte tells us how many bytes encode the length
            int numBytes = firstByte & 0x7F;
            int length = 0;
            for (int i = 0; i < numBytes; i++) {
                length = (length << 8) | (data[pos[0]++] & 0xFF);
            }
            return length;
        }
    }

    // ----------------------------------------------------------------
    // READ TAG FROM BER ENCODED BYTES
    // ----------------------------------------------------------------
    public static int readTag(byte[] data, int[] pos) {
        return data[pos[0]++] & 0xFF;
    }

    // ----------------------------------------------------------------
    // READ BYTES AS STRING
    // ----------------------------------------------------------------
    public static String readString(byte[] data, int offset, int length) {
        try {
            return new String(data, offset, length, "UTF-8");
        } catch (Exception e) {
            return "";
        }
    }

    // ----------------------------------------------------------------
    // READ INTEGER VALUE FROM BER BYTES
    // ----------------------------------------------------------------
    public static int readInteger(byte[] data, int offset, int length) {
        int value = 0;
        for (int i = 0; i < length; i++) {
            value = (value << 8) | (data[offset + i] & 0xFF);
        }
        return value;
    }

    // ----------------------------------------------------------------
    // DECODE A COMPLETE LDAP RESPONSE PACKET
    // RFC 4511 Section 4.1.1
    // LDAPMessage ::= SEQUENCE { messageID, protocolOp }
    // ----------------------------------------------------------------
    public static LdapResponse decode(byte[] data) {
        LdapResponse response = new LdapResponse();
        int[] pos = { 0 };

        // Read outer SEQUENCE tag
        int outerTag = readTag(data, pos);
        if (outerTag != BerEncoder.TAG_SEQUENCE) {
            System.err.println("ERROR: Expected SEQUENCE tag 0x30, got: " +
                String.format("0x%02X", outerTag));
            return response;
        }

        // Read outer SEQUENCE length
        int outerLength = readLength(data, pos);

        // Read messageID
        // messageID ::= INTEGER
        int msgIdTag    = readTag(data, pos);
        int msgIdLength = readLength(data, pos);
        response.messageId = readInteger(data, pos[0], msgIdLength);
        pos[0] += msgIdLength;

        // Read protocol operation tag
        response.responseTag = readTag(data, pos);
        int opLength = readLength(data, pos);
        int opStart  = pos[0];

        System.out.println("DEBUG: Response tag: " +
            String.format("0x%02X", response.responseTag) +
            " messageId: " + response.messageId);

        // Decode based on response type
        if (response.isBindResponse()) {
            decodeBindResponse(data, pos, response);
        } else if (response.isSearchEntry()) {
            decodeSearchEntry(data, pos, opStart, opLength, response);
        } else if (response.isSearchDone()) {
            decodeSearchDone(data, pos, response);
        } else {
            System.out.println("DEBUG: Unknown response tag: " +
                String.format("0x%02X", response.responseTag));
        }

        return response;
    }

    // ----------------------------------------------------------------
    // DECODE BIND RESPONSE (RFC 4511 Section 4.2.2)
    // BindResponse ::= [APPLICATION 1] SEQUENCE {
    //     COMPONENTS OF LDAPResult
    // }
    // LDAPResult ::= SEQUENCE {
    //     resultCode  ENUMERATED,
    //     matchedDN   LDAPDN,
    //     errorMessage LDAPString
    // }
    // ----------------------------------------------------------------
    private static void decodeBindResponse(byte[] data, int[] pos,
                                           LdapResponse response) {
        decodeLdapResult(data, pos, response);
    }

    // ----------------------------------------------------------------
    // DECODE SEARCH RESULT ENTRY (RFC 4511 Section 4.5.2)
    // SearchResultEntry ::= [APPLICATION 4] SEQUENCE {
    //     objectName LDAPDN,
    //     attributes PartialAttributeList
    // }
    // ----------------------------------------------------------------
    private static void decodeSearchEntry(byte[] data, int[] pos,
                                          int opStart, int opLength,
                                          LdapResponse response) {
        // Read objectName (the DN of this entry)
        int dnTag    = readTag(data, pos);
        int dnLength = readLength(data, pos);
        String dn    = readString(data, pos[0], dnLength);
        pos[0] += dnLength;

        LdapEntry entry = new LdapEntry(dn);

        // Read PartialAttributeList — SEQUENCE OF PartialAttribute
        int attrListTag    = readTag(data, pos);
        int attrListLength = readLength(data, pos);
        int attrListEnd    = pos[0] + attrListLength;

        // Each PartialAttribute ::= SEQUENCE { type, vals SET OF value }
        while (pos[0] < attrListEnd) {
            int attrSeqTag    = readTag(data, pos);
            int attrSeqLength = readLength(data, pos);
            int attrSeqEnd    = pos[0] + attrSeqLength;

            // Read attribute type (name)
            int typeTag    = readTag(data, pos);
            int typeLength = readLength(data, pos);
            String attrName = readString(data, pos[0], typeLength);
            pos[0] += typeLength;

            LdapAttribute attribute = new LdapAttribute(attrName);

            // Read attribute values SET
            int setTag    = readTag(data, pos);
            int setLength = readLength(data, pos);
            int setEnd    = pos[0] + setLength;

            while (pos[0] < setEnd) {
                int valTag    = readTag(data, pos);
                int valLength = readLength(data, pos);
                String value  = readString(data, pos[0], valLength);
                pos[0] += valLength;
                attribute.values.add(value);
            }

            entry.attributes.add(attribute);
            pos[0] = attrSeqEnd;
        }

        response.entries.add(entry);
    }

    // ----------------------------------------------------------------
    // DECODE SEARCH RESULT DONE (RFC 4511 Section 4.5.2)
    // SearchResultDone ::= [APPLICATION 5] LDAPResult
    // ----------------------------------------------------------------
    private static void decodeSearchDone(byte[] data, int[] pos,
                                         LdapResponse response) {
        decodeLdapResult(data, pos, response);
    }

    // ----------------------------------------------------------------
    // DECODE LDAPResult (RFC 4511 Section 4.1.9)
    // LDAPResult ::= SEQUENCE {
    //     resultCode   ENUMERATED,
    //     matchedDN    LDAPDN,
    //     errorMessage LDAPString,
    //     referral     [3] Referral OPTIONAL
    // }
    // ----------------------------------------------------------------
    private static void decodeLdapResult(byte[] data, int[] pos,
                                         LdapResponse response) {
        // Result code
        int resultCodeTag    = readTag(data, pos);
        int resultCodeLength = readLength(data, pos);
        response.resultCode  = readInteger(data, pos[0], resultCodeLength);
        pos[0] += resultCodeLength;

        // Matched DN
        int matchedDNTag    = readTag(data, pos);
        int matchedDNLength = readLength(data, pos);
        response.matchedDN  = readString(data, pos[0], matchedDNLength);
        pos[0] += matchedDNLength;

        // Error message
        int errorMsgTag    = readTag(data, pos);
        int errorMsgLength = readLength(data, pos);
        response.errorMessage = readString(data, pos[0], errorMsgLength);
        pos[0] += errorMsgLength;

        System.out.println("DEBUG: Result code: " + response.resultCode +
            " (" + getResultCodeMeaning(response.resultCode) + ")" +
            (response.errorMessage.isEmpty() ? "" :
             " - " + response.errorMessage));
    }

    // ----------------------------------------------------------------
    // DEBUG HELPER — print decoded response summary
    // ----------------------------------------------------------------
    public static void printResponse(LdapResponse response) {
        System.out.println("=== LDAP Response ===");
        System.out.println("Message ID : " + response.messageId);
        System.out.println("Tag        : " +
            String.format("0x%02X", response.responseTag));
        if (response.resultCode >= 0) {
            System.out.println("Result     : " + response.resultCode +
                " (" + getResultCodeMeaning(response.resultCode) + ")");
        }
        if (!response.matchedDN.isEmpty()) {
            System.out.println("Matched DN : " + response.matchedDN);
        }
        if (!response.errorMessage.isEmpty()) {
            System.out.println("Error      : " + response.errorMessage);
        }
        for (LdapEntry entry : response.entries) {
            System.out.println("Entry      : " + entry.dn);
            for (LdapAttribute attr : entry.attributes) {
                System.out.println("  " + attr.name + ": " + attr.values);
            }
        }
        System.out.println("====================");
    }
}