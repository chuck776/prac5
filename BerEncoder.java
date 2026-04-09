//importing necessary Java libraries for networking, I/O, and data structures
import java.io.ByteArrayOutputStream;
import java.io.IOException;


//this class provides static methods to encode various LDAP protocol messages into BER format. It includes methods for encoding primitive types (integers, strings, booleans) as well as constructed types (sequences, sets, application-specific messages). The main purpose of this class is to build
public class BerEncoder {

    // ----------------------------------------------------------------
    // BER TAG CONSTANTS (RFC 4511)
    // in compliance with RFC 4511, we define constants for the relevant BER tags used in LDAP messages. 
    // These include universal tags for basic types (INTEGER, OCTET STRING, BOOLEAN, ENUMERATED) as well as application-specific tags for LDAP operations (BIND, SEARCH, MODIFY, etc.) and context-specific tags for filters. These constants help ensure that our encoding methods use the correct tag values when constructing BER-encoded messages.
    // ----------------------------------------------------------------
    public static final int TAG_INTEGER         = 0x02;
    public static final int TAG_OCTET_STRING    = 0x04;
    public static final int TAG_BOOLEAN         = 0x01;
    public static final int TAG_ENUMERATED      = 0x0A;
    public static final int TAG_SEQUENCE        = 0x30;
    public static final int TAG_SET             = 0x31;

    // LDAP Application tags (RFC 4511 Section 4)
    public static final int TAG_BIND_REQUEST    = 0x60; // [APPLICATION 0]
    public static final int TAG_BIND_RESPONSE   = 0x61; // [APPLICATION 1]
    public static final int TAG_UNBIND_REQUEST  = 0x42; // [APPLICATION 2] primitive
    public static final int TAG_SEARCH_REQUEST  = 0x63; // [APPLICATION 3]
    public static final int TAG_SEARCH_ENTRY    = 0x64; // [APPLICATION 4]
    public static final int TAG_SEARCH_DONE     = 0x65; // [APPLICATION 5]
    public static final int TAG_MODIFY_REQUEST  = 0x66; // [APPLICATION 6]
    public static final int TAG_MODIFY_RESPONSE = 0x67; // [APPLICATION 7]
    public static final int TAG_ADD_REQUEST     = 0x68; // [APPLICATION 8]
    public static final int TAG_ADD_RESPONSE    = 0x69; // [APPLICATION 9]
    public static final int TAG_DELETE_REQUEST  = 0x4A; // [APPLICATION 10] primitive
    public static final int TAG_DELETE_RESPONSE = 0x6B; // [APPLICATION 11]

    // Context / filter tags
    public static final int TAG_SIMPLE_AUTH         = 0x80; // [0] PRIMITIVE  — simple password
    public static final int TAG_EQUALITY_MATCH      = 0xA3; // [3] CONSTRUCTED — equalityMatch filter
    public static final int TAG_GREATER_OR_EQUAL    = 0xA5; // [5] CONSTRUCTED — greaterOrEqual filter
    public static final int TAG_ATTRIBUTES          = 0x30; // SEQUENCE OF

    // ----------------------------------------------------------------
    // ENCODE LENGTH (BER definite form — RFC 4511 Section 5.1)
    // according to BER encoding rules, lengths less than 128 are encoded in a single byte. For lengths 128 or greater, the first byte indicates how many subsequent bytes are used to represent the length, followed by the length bytes themselves. This method implements this logic to produce the correct BER-encoded length field for any given input length.
    // ----------------------------------------------------------------
    public static byte[] encodeLength(int length) {
        if (length < 128) {
            return new byte[]{ (byte) length };
        } else if (length < 256) {
            return new byte[]{ (byte) 0x81, (byte) length };
        } else {
            return new byte[]{
                (byte) 0x82,
                (byte) ((length >> 8) & 0xFF),
                (byte) (length & 0xFF)
            };
        }
    }

    // ----------------------------------------------------------------
    // ENCODE TLV — Tag, Length, Value
    // This method takes a tag and a value byte array, encodes the length of the value using the encodeLength method, and constructs the final TLV byte array by concatenating the tag, length bytes, and value bytes. This is a fundamental building block for all BER-encoded messages, as it allows us to create properly formatted TLV structures for any type of data.
    // ----------------------------------------------------------------
    public static byte[] encodeTLV(int tag, byte[] value) {
        byte[] lengthBytes = encodeLength(value.length);
        byte[] result = new byte[1 + lengthBytes.length + value.length];
        result[0] = (byte) tag;
        System.arraycopy(lengthBytes, 0, result, 1, lengthBytes.length);
        System.arraycopy(value, 0, result, 1 + lengthBytes.length, value.length);
        return result;
    }

    // ----------------------------------------------------------------
    // ENCODE PRIMITIVE TYPES
    // these methods encode basic data types according to BER rules. For integers, we determine the minimum number of bytes needed to represent the value and encode it accordingly. For strings, we convert them to UTF-8 byte arrays. Booleans are encoded as a single byte (0xFF for true, 0x00 for false). Enumerated values are also encoded as a single byte. Context-specific primitives (like simple authentication) are encoded with their specific context tag.
    // ----------------------------------------------------------------
    

    // For INTEGER, we check the value range to determine how many bytes are needed for encoding. Values between -128 and 127 can be encoded in a single byte, while larger values require 2 or 4 bytes. We then construct the TLV using the appropriate tag and value bytes.
    public static byte[] encodeInteger(int value) {
        if (value >= -128 && value <= 127) {
            return encodeTLV(TAG_INTEGER, new byte[]{ (byte) value });
        } else if (value >= -32768 && value <= 32767) {
            return encodeTLV(TAG_INTEGER, new byte[]{
                (byte) ((value >> 8) & 0xFF),
                (byte) (value & 0xFF)
            });
        } else {
            return encodeTLV(TAG_INTEGER, new byte[]{
                (byte) ((value >> 24) & 0xFF),
                (byte) ((value >> 16) & 0xFF),
                (byte) ((value >> 8)  & 0xFF),
                (byte) (value & 0xFF)
            });
        }
    }
    // For OCTET STRING, we convert the input string to UTF-8 bytes and then encode it as a TLV with the appropriate tag. 
    // If there is an encoding error, we return an empty OCTET STRING.
    public static byte[] encodeOctetString(String value) {
        try {
            byte[] strBytes = value.getBytes("UTF-8");
            return encodeTLV(TAG_OCTET_STRING, strBytes);
        } catch (Exception e) {
            return encodeTLV(TAG_OCTET_STRING, new byte[0]);
        }
    }
    // for ENUMERATED, we simply encode the integer value as a single byte and construct the TLV with the ENUMERATED tag. This is sufficient for LDAP filters where enumerated values typically represent small integers.
    public static byte[] encodeEnumerated(int value) {
        return encodeTLV(TAG_ENUMERATED, new byte[]{ (byte) value });
    }
    // for BOOLEAN, we encode true as 0xFF and false as 0x00, following BER encoding rules. We then construct the TLV with the BOOLEAN tag.
    public static byte[] encodeBoolean(boolean value) {
        return encodeTLV(TAG_BOOLEAN, new byte[]{ value ? (byte) 0xFF : (byte) 0x00 });
    }
    // for context-specific primitives like simple authentication, we use the provided context tag and encode the string value as UTF-8 bytes. We then construct the TLV using the context tag and the encoded string bytes. If there is an encoding error, we return an empty value with the context tag.
    public static byte[] encodeContextPrimitive(int contextTag, String value) {
        try {
            byte[] strBytes = value.getBytes("UTF-8");
            return encodeTLV(contextTag, strBytes);
        } catch (Exception e) {
            return encodeTLV(contextTag, new byte[0]);
        }
    }

    // ----------------------------------------------------------------
    // ENCODE CONSTRUCTED TYPES
    // these methods encode constructed types like SEQUENCE and SET by taking the content bytes (which may themselves be TLVs) and wrapping them with the appropriate tag and length. For application-specific messages, we use the provided application tag. The concat method is a helper that concatenates multiple byte arrays into one, which is useful for building the content of sequences and sets. 
    // ----------------------------------------------------------------

    public static byte[] concat(byte[]... arrays) {
        int totalLength = 0;
        for (byte[] arr : arrays) totalLength += arr.length;
        byte[] result = new byte[totalLength];
        int pos = 0;
        for (byte[] arr : arrays) {
            System.arraycopy(arr, 0, result, pos, arr.length);
            pos += arr.length;
        }
        return result;
    }

    public static byte[] encodeSequence(byte[] content) {
        return encodeTLV(TAG_SEQUENCE, content);
    }

    public static byte[] encodeSet(byte[] content) {
        return encodeTLV(TAG_SET, content);
    }

    public static byte[] encodeApplication(int appTag, byte[] content) {
        return encodeTLV(appTag, content);
    }

    // ----------------------------------------------------------------
    // BUILD LDAP MESSAGE WRAPPER
    // according to RFC 4511, every LDAP message is a SEQUENCE that contains a messageID (INTEGER) and a protocolOp (which is a CHOICE of different application-specific messages). This method takes a message ID and the already-encoded protocol operation bytes, constructs the content of the SEQUENCE by concatenating the encoded message ID and protocol operation, and then wraps it in a SEQUENCE TLV to produce the final LDAPMessage byte array.
    // LDAPMessage ::= SEQUENCE { messageID INTEGER, protocolOp CHOICE }
    // ----------------------------------------------------------------
    public static byte[] buildLdapMessage(int messageId, byte[] protocolOp) {
        byte[] msgIdBytes = encodeInteger(messageId);
        byte[] content    = concat(msgIdBytes, protocolOp);
        return encodeSequence(content);
    }

    // ----------------------------------------------------------------
    // BUILD BIND REQUEST (RFC 4511 Section 4.2)
    // BindRequest ::= [APPLICATION 0] SEQUENCE {
    //     version INTEGER (1..127),
    //     name    LDAPDN,
    //     authentication AuthenticationChoice }
    // ----------------------------------------------------------------
    public static byte[] buildBindRequest(int messageId,
                                          String bindDN,
                                          String password) {
        byte[] version        = encodeInteger(3);
        byte[] name           = encodeOctetString(bindDN);
        byte[] auth           = encodeContextPrimitive(TAG_SIMPLE_AUTH, password);
        byte[] bindReqContent = concat(version, name, auth);
        byte[] bindReq        = encodeApplication(TAG_BIND_REQUEST, bindReqContent);
        return buildLdapMessage(messageId, bindReq);
    }

    public static byte[] buildAnonymousBindRequest(int messageId) {
        return buildBindRequest(messageId, "", "");
    }

    // ----------------------------------------------------------------
    // BUILD SEARCH REQUEST — equality match (RFC 4511 Section 4.5)
    // ----------------------------------------------------------------
    public static byte[] buildSearchRequest(int messageId,
                                            String baseDN,
                                            String searchAttribute,
                                            String searchValue) {
        byte[] filter = buildEqualityFilter(searchAttribute, searchValue);
        return buildSearchRequestWithFilter(messageId, baseDN, filter);
    }

    // ----------------------------------------------------------------
    // BUILD SEARCH REQUEST — greaterOrEqual filter (RFC 4511 Section 4.5.1)
    // Filter ::= CHOICE { greaterOrEqual [5] AttributeValueAssertion }
    // AttributeValueAssertion ::= SEQUENCE { attributeDesc, assertionValue }
    // Tag 0xA5 = context class (10), constructed (1), tag number 5
    // ----------------------------------------------------------------
    public static byte[] buildSearchRequestGreaterOrEqual(int messageId,
                                                          String baseDN,
                                                          String attribute,
                                                          String value) {
        byte[] filter = buildGreaterOrEqualFilter(attribute, value);
        return buildSearchRequestWithFilter(messageId, baseDN, filter);
    }

    // ----------------------------------------------------------------
    // SHARED SEARCH REQUEST BUILDER — accepts any pre-built filter bytes
    // ----------------------------------------------------------------
    private static byte[] buildSearchRequestWithFilter(int messageId,
                                                       String baseDN,
                                                       byte[] filter) {
        byte[] base         = encodeOctetString(baseDN);
        byte[] scope        = encodeEnumerated(2); // wholeSubtree
        byte[] derefAliases = encodeEnumerated(0); // neverDerefAliases
        byte[] sizeLimit    = encodeInteger(0);    // no limit
        byte[] timeLimit    = encodeInteger(0);    // no limit
        byte[] typesOnly    = encodeBoolean(false);
        byte[] attributes   = encodeSequence(new byte[0]); // return all attrs

        byte[] searchContent = concat(base, scope, derefAliases,
                                      sizeLimit, timeLimit,
                                      typesOnly, filter, attributes);
        byte[] searchReq = encodeApplication(TAG_SEARCH_REQUEST, searchContent);
        return buildLdapMessage(messageId, searchReq);
    }

    // ----------------------------------------------------------------
    // FILTER BUILDERS
    // ----------------------------------------------------------------

    // equalityMatch [3] AttributeValueAssertion
    public static byte[] buildEqualityFilter(String attribute, String value) {
        byte[] attrDesc    = encodeOctetString(attribute);
        byte[] assertValue = encodeOctetString(value);
        byte[] avaContent  = concat(attrDesc, assertValue);
        return encodeTLV(TAG_EQUALITY_MATCH, avaContent);
    }

    // greaterOrEqual [5] AttributeValueAssertion
    // RFC 4511 Section 4.5.1: same ASN.1 structure as equalityMatch,
    // but with context tag [5] (0xA5) instead of [3] (0xA3)
    public static byte[] buildGreaterOrEqualFilter(String attribute, String value) {
        byte[] attrDesc    = encodeOctetString(attribute);
        byte[] assertValue = encodeOctetString(value);
        byte[] avaContent  = concat(attrDesc, assertValue);
        return encodeTLV(TAG_GREATER_OR_EQUAL, avaContent);
    }

    // ----------------------------------------------------------------
    // BUILD ADD REQUEST (RFC 4511 Section 4.7)
    // AddRequest ::= [APPLICATION 8] SEQUENCE {
    //     entry      LDAPDN,
    //     attributes AttributeList }
    // AttributeList ::= SEQUENCE OF Attribute
    // Attribute ::= PartialAttribute (same encoding)
    // PartialAttribute ::= SEQUENCE { type AttributeDescription,
    //                                 vals SET OF value }
    // ----------------------------------------------------------------
    public static byte[] buildAddRequest(int messageId,
                                         String entryDN,
                                         String[][] attributes) {
        byte[] entry = encodeOctetString(entryDN);

        // Build AttributeList
        byte[] attrList = new byte[0];
        for (String[] attr : attributes) {
            // attr[0] = attribute name, attr[1..n] = values
            byte[] attrType = encodeOctetString(attr[0]);

            // Build SET OF values
            byte[] valuesContent = new byte[0];
            for (int i = 1; i < attr.length; i++) {
                valuesContent = concat(valuesContent, encodeOctetString(attr[i]));
            }
            byte[] valSet   = encodeSet(valuesContent);
            byte[] attrSeq  = encodeSequence(concat(attrType, valSet));
            attrList        = concat(attrList, attrSeq);
        }

        byte[] attrListSeq  = encodeSequence(attrList);
        byte[] addContent   = concat(entry, attrListSeq);
        byte[] addReq       = encodeApplication(TAG_ADD_REQUEST, addContent);
        return buildLdapMessage(messageId, addReq);
    }

    // ----------------------------------------------------------------
    // BUILD DELETE REQUEST (RFC 4511 Section 4.8)
    // DelRequest ::= [APPLICATION 10] LDAPDN
    // Tag 0x4A = application class (01), primitive (0), tag 10
    // The value is simply the UTF-8 bytes of the DN — no inner TLV
    // ----------------------------------------------------------------
    public static byte[] buildDeleteRequest(int messageId, String entryDN) {
        try {
            byte[] dnBytes = entryDN.getBytes("UTF-8");
            byte[] delReq  = encodeTLV(TAG_DELETE_REQUEST, dnBytes);
            return buildLdapMessage(messageId, delReq);
        } catch (Exception e) {
            byte[] delReq = encodeTLV(TAG_DELETE_REQUEST, new byte[0]);
            return buildLdapMessage(messageId, delReq);
        }
    }

    // ----------------------------------------------------------------
    // BUILD MODIFY REQUEST (RFC 4511 Section 4.6)
    // ModifyRequest ::= [APPLICATION 6] SEQUENCE {
    //     object   LDAPDN,
    //     changes  SEQUENCE OF change }
    // change ::= SEQUENCE {
    //     operation ENUMERATED { add(0), delete(1), replace(2) },
    //     modification PartialAttribute }
    // PartialAttribute ::= SEQUENCE { type, vals SET OF value }
    // ----------------------------------------------------------------
    public static final int MODIFY_OP_ADD     = 0;
    public static final int MODIFY_OP_DELETE  = 1;
    public static final int MODIFY_OP_REPLACE = 2;

    public static byte[] buildModifyRequest(int messageId,
                                            String entryDN,
                                            int operation,
                                            String attrName,
                                            String[] values) {
        byte[] object = encodeOctetString(entryDN);

        // Build the PartialAttribute: SEQUENCE { type, vals SET OF value }
        byte[] attrType      = encodeOctetString(attrName);
        byte[] valuesContent = new byte[0];
        for (String v : values) {
            valuesContent = concat(valuesContent, encodeOctetString(v));
        }
        byte[] valSet        = encodeSet(valuesContent);
        byte[] partialAttr   = encodeSequence(concat(attrType, valSet));

        // Build change: SEQUENCE { operation ENUMERATED, modification }
        byte[] op     = encodeEnumerated(operation);
        byte[] change = encodeSequence(concat(op, partialAttr));

        // changes ::= SEQUENCE OF change  (just one change here)
        byte[] changes    = encodeSequence(change);

        byte[] modContent = concat(object, changes);
        byte[] modReq     = encodeApplication(TAG_MODIFY_REQUEST, modContent);
        return buildLdapMessage(messageId, modReq);
    }

    // ----------------------------------------------------------------
    // BUILD UNBIND REQUEST (RFC 4511 Section 4.3)
    // UnbindRequest ::= [APPLICATION 2] NULL
    // ----------------------------------------------------------------
    public static byte[] buildUnbindRequest(int messageId) {
        byte[] unbindReq = new byte[]{ (byte) TAG_UNBIND_REQUEST, 0x00 };
        return buildLdapMessage(messageId, unbindReq);
    }

    // ----------------------------------------------------------------
    // DEBUG HELPER
    // helper method to convert byte arrays to a hex string for debugging purposes. This allows us to visualize the raw bytes of the encoded messages, which can be useful for verifying correctness and troubleshooting encoding issues.
    // ----------------------------------------------------------------
    public static String toHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02X ", b));
        }
        return sb.toString().trim();
    }
}