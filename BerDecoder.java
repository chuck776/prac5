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
    // PARSED ATTRIBUTE
    //this class represents a parsed LDAP attribute, containing the attribute name and a list of values. It provides a toString method for easy display of the attribute's contents.
    // ----------------------------------------------------------------
    public static class LdapAttribute {
        public String name;
        public List<String> values = new ArrayList<>();

        public LdapAttribute(String name) { this.name = name; }

        @Override
        public String toString() { return name + ": " + values; }
    }

    // ----------------------------------------------------------------
    // PARSED ENTRY
    // this class represents a parsed LDAP entry, containing the distinguished name (DN) and a list of attributes. It provides a method to retrieve the value of a specific attribute by name, and a toString method for easy display of the entry's contents.
    // ----------------------------------------------------------------
    public static class LdapEntry {
        public String dn;
        public List<LdapAttribute> attributes = new ArrayList<>();

        public LdapEntry(String dn) { this.dn = dn; }

        public String getAttributeValue(String attrName) {
            for (LdapAttribute attr : attributes) {
                if (attr.name.equalsIgnoreCase(attrName)) {
                    if (!attr.values.isEmpty()) return attr.values.get(0);
                }
            }
            return null;
        }

        @Override
        public String toString() {
            StringBuilder sb = new StringBuilder();
            sb.append("DN: ").append(dn).append("\n");
            for (LdapAttribute attr : attributes) {
                for (String val : attr.values) {
                    sb.append("  ").append(attr.name).append(": ").append(val).append("\n");
                }
            }
            return sb.toString();
        }
    }

    // ----------------------------------------------------------------
    // PARSED LDAP RESPONSE
    // parsed LDAP response containing the message ID, response tag, result code, matched DN, error message, and any entries returned in a search response. It also includes helper methods to check the type of response (e.g., is it a search entry, search done, bind response, etc.) based on the response tag. This class serves as a structured representation of the decoded LDAP response for easier access and manipulation in the application.
    // ----------------------------------------------------------------
    public static class LdapResponse {
        public int messageId;
        public int responseTag;
        public int resultCode      = -1;
        public String matchedDN    = "";
        public String errorMessage = "";
        public List<LdapEntry> entries = new ArrayList<>();

        public boolean isSuccess()      { return resultCode == 0; }
        public boolean isSearchEntry()  { return responseTag == BerEncoder.TAG_SEARCH_ENTRY; }
        public boolean isSearchDone()   { return responseTag == BerEncoder.TAG_SEARCH_DONE; }
        public boolean isBindResponse() { return responseTag == BerEncoder.TAG_BIND_RESPONSE; }

        // RFC 4511 Section 4.7 — AddResponse
        public boolean isAddResponse()    { return responseTag == BerEncoder.TAG_ADD_RESPONSE; }
        // RFC 4511 Section 4.8 — DelResponse
        public boolean isDeleteResponse() { return responseTag == BerEncoder.TAG_DELETE_RESPONSE; }
        // RFC 4511 Section 4.6 — ModifyResponse
        public boolean isModifyResponse() { return responseTag == BerEncoder.TAG_MODIFY_RESPONSE; }
    }

    // ----------------------------------------------------------------
    // READ LENGTH
    //this method reads the length of a BER-encoded element from the byte array. It handles both short form (where the length is less than 128 and fits in one byte) and long form (where the first byte indicates how many subsequent bytes are used to represent the length). The method updates the position index as it reads bytes from the array.
    // ----------------------------------------------------------------
    public static int readLength(byte[] data, int[] pos) {
        int firstByte = data[pos[0]++] & 0xFF;
        if (firstByte < 128) {
            return firstByte;
        } else {
            int numBytes = firstByte & 0x7F;
            int length = 0;
            for (int i = 0; i < numBytes; i++) {
                length = (length << 8) | (data[pos[0]++] & 0xFF);
            }
            return length;
        }
    }

    public static int readTag(byte[] data, int[] pos) {
        return data[pos[0]++] & 0xFF;
    }

    public static String readString(byte[] data, int offset, int length) {
        try {
            return new String(data, offset, length, "UTF-8");
        } catch (Exception e) {
            return "";
        }
    }

    public static int readInteger(byte[] data, int offset, int length) {
        int value = 0;
        for (int i = 0; i < length; i++) {
            value = (value << 8) | (data[offset + i] & 0xFF);
        }
        return value;
    }

    // ----------------------------------------------------------------
    // DECODE A COMPLETE LDAP RESPONSE PACKET
    // LDAPMessage ::= SEQUENCE { messageID, protocolOp }
    // function to decode a complete LDAP response packet from a byte array. It first reads the outer SEQUENCE tag and length, then extracts the message ID and protocol operation.
    //  Based on the protocol operation tag, it determines the type of response (e.g., BindResponse, SearchResultEntry, SearchResultDone) and calls the appropriate decoding function to parse the contents of the response. 
    // The decoded information is stored in an LdapResponse object, which can be used for further processing or display.
    // ----------------------------------------------------------------
    public static LdapResponse decode(byte[] data) {
        LdapResponse response = new LdapResponse();
        int[] pos = { 0 };

        int outerTag = readTag(data, pos);
        if (outerTag != BerEncoder.TAG_SEQUENCE) {
            System.err.println("ERROR: Expected SEQUENCE tag 0x30, got: " +
                String.format("0x%02X", outerTag));
            return response;
        }

        int outerLength = readLength(data, pos);

        // messageID
        int msgIdTag    = readTag(data, pos);
        int msgIdLength = readLength(data, pos);
        response.messageId = readInteger(data, pos[0], msgIdLength);
        pos[0] += msgIdLength;

        // protocol operation
        response.responseTag = readTag(data, pos);
        int opLength = readLength(data, pos);
        int opStart  = pos[0];

        System.out.println("DEBUG: Response tag: " +
            String.format("0x%02X", response.responseTag) +
            " messageId: " + response.messageId);

        if (response.isBindResponse()) {
            decodeLdapResult(data, pos, response);
        } else if (response.isSearchEntry()) {
            decodeSearchEntry(data, pos, opStart, opLength, response);
        } else if (response.isSearchDone()) {
            decodeLdapResult(data, pos, response);
        } else if (response.isAddResponse()) {
            // AddResponse ::= [APPLICATION 9] LDAPResult
            decodeLdapResult(data, pos, response);
        } else if (response.isDeleteResponse()) {
            // DelResponse ::= [APPLICATION 11] LDAPResult
            decodeLdapResult(data, pos, response);
        } else if (response.isModifyResponse()) {
            // ModifyResponse ::= [APPLICATION 7] LDAPResult
            decodeLdapResult(data, pos, response);
        } else {
            System.out.println("DEBUG: Unknown response tag: " +
                String.format("0x%02X", response.responseTag));
        }

        return response;
    }

    // ----------------------------------------------------------------
    // DECODE SEARCH RESULT ENTRY (RFC 4511 Section 4.5.2)
    // SearchResultEntry ::= [APPLICATION 4] SEQUENCE {
    //     objectName LDAPDN,
    //     attributes PartialAttributeList }
    // this also decodes the DN and attributes of a search result entry. It reads the objectName (DN) as a string and then iterates through the attributes, decoding each attribute's name and values. The decoded entry is stored in the LdapResponse object for later use or display.
    // ----------------------------------------------------------------
    private static void decodeSearchEntry(byte[] data, int[] pos,
                                          int opStart, int opLength,
                                          LdapResponse response) {
        int dnTag    = readTag(data, pos);
        int dnLength = readLength(data, pos);
        String dn    = readString(data, pos[0], dnLength);
        pos[0] += dnLength;

        LdapEntry entry = new LdapEntry(dn);

        int attrListTag    = readTag(data, pos);
        int attrListLength = readLength(data, pos);
        int attrListEnd    = pos[0] + attrListLength;

        while (pos[0] < attrListEnd) {
            int attrSeqTag    = readTag(data, pos);
            int attrSeqLength = readLength(data, pos);
            int attrSeqEnd    = pos[0] + attrSeqLength;

            int typeTag    = readTag(data, pos);
            int typeLength = readLength(data, pos);
            String attrName = readString(data, pos[0], typeLength);
            pos[0] += typeLength;

            LdapAttribute attribute = new LdapAttribute(attrName);

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
    // DECODE LDAPResult (RFC 4511 Section 4.1.9)
    // LDAPResult ::= SEQUENCE {
    //     resultCode   ENUMERATED,
    //     matchedDN    LDAPDN,
    //     errorMessage LDAPString,
    //     referral     [3] Referral OPTIONAL }
    // Used by: BindResponse, SearchResultDone, AddResponse,
    //          DelResponse, ModifyResponse
    // this also decodes the result code, matched DN, and error message from the response. It reads the result code as an enumerated value, the matched DN as a string, and the error message as a string. The decoded values are stored in the LdapResponse object for later use or display.
    // ----------------------------------------------------------------
    private static void decodeLdapResult(byte[] data, int[] pos,
                                         LdapResponse response) {
        int resultCodeTag    = readTag(data, pos);
        int resultCodeLength = readLength(data, pos);
        response.resultCode  = readInteger(data, pos[0], resultCodeLength);
        pos[0] += resultCodeLength;

        int matchedDNTag    = readTag(data, pos);
        int matchedDNLength = readLength(data, pos);
        response.matchedDN  = readString(data, pos[0], matchedDNLength);
        pos[0] += matchedDNLength;

        int errorMsgTag    = readTag(data, pos);
        int errorMsgLength = readLength(data, pos);
        response.errorMessage = readString(data, pos[0], errorMsgLength);
        pos[0] += errorMsgLength;

        System.out.println("DEBUG: Result code: " + response.resultCode +
            " (" + getResultCodeMeaning(response.resultCode) + ")" +
            (response.errorMessage.isEmpty() ? "" : " - " + response.errorMessage));
    }

    // ----------------------------------------------------------------
    // DEBUG HELPER
    // function to print the contents of a parsed LDAP response in a human-readable format. This is useful for debugging and verifying that the decoding process is working correctly. It displays the message ID, response tag, result code (with meaning), matched DN, error message, and any entries returned in a search response.
    // ----------------------------------------------------------------
    public static void printResponse(LdapResponse response) {
        System.out.println("=== LDAP Response ===");
        System.out.println("Message ID : " + response.messageId);
        System.out.println("Tag        : " + String.format("0x%02X", response.responseTag));
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