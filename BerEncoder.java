import java.io.ByteArrayOutputStream;
import java.io.IOException;

public class BerEncoder {

    // ----------------------------------------------------------------
    // BER TAG CONSTANTS (RFC 4511)
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
    public static final int TAG_UNBIND_REQUEST  = 0x42; // [APPLICATION 2]
    public static final int TAG_SEARCH_REQUEST  = 0x63; // [APPLICATION 3]
    public static final int TAG_SEARCH_ENTRY    = 0x64; // [APPLICATION 4]
    public static final int TAG_SEARCH_DONE     = 0x65; // [APPLICATION 5]
    public static final int TAG_MODIFY_RESPONSE = 0x67; // [APPLICATION 7]

    // Context tags used in filters and authentication
    public static final int TAG_SIMPLE_AUTH     = 0x80; // [0] PRIMITIVE
    public static final int TAG_EQUALITY_MATCH  = 0xA3; // [3] CONSTRUCTED
    public static final int TAG_ATTRIBUTES      = 0x30; // SEQUENCE OF

    // ----------------------------------------------------------------
    // ENCODE LENGTH (BER definite form - RFC 4511 Section 5.1)
    // ----------------------------------------------------------------
    // If length < 128: single byte
    // If length >= 128: first byte = 0x80 + number of length bytes,
    //                   followed by length in big-endian bytes
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
    // ----------------------------------------------------------------

    // Encode an INTEGER value
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

    // Encode an OCTET STRING (used for all strings in LDAP)
    public static byte[] encodeOctetString(String value) {
        try {
            byte[] strBytes = value.getBytes("UTF-8");
            return encodeTLV(TAG_OCTET_STRING, strBytes);
        } catch (Exception e) {
            return encodeTLV(TAG_OCTET_STRING, new byte[0]);
        }
    }

    // Encode an ENUMERATED value (used for scope, derefAliases etc.)
    public static byte[] encodeEnumerated(int value) {
        return encodeTLV(TAG_ENUMERATED, new byte[]{ (byte) value });
    }

    // Encode a BOOLEAN value
    public static byte[] encodeBoolean(boolean value) {
        return encodeTLV(TAG_BOOLEAN, new byte[]{ value ? (byte) 0xFF : (byte) 0x00 });
    }

    // Encode a context-specific primitive (e.g. simple auth password)
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
    // ----------------------------------------------------------------

    // Concatenate multiple byte arrays into one
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

    // Wrap content in a SEQUENCE
    public static byte[] encodeSequence(byte[] content) {
        return encodeTLV(TAG_SEQUENCE, content);
    }

    // Wrap content in a specific application tag
    public static byte[] encodeApplication(int appTag, byte[] content) {
        return encodeTLV(appTag, content);
    }

    // ----------------------------------------------------------------
    // BUILD COMPLETE LDAP MESSAGES (RFC 4511 Section 4)
    // ----------------------------------------------------------------

    // Build an LDAPMessage wrapper
    // LDAPMessage ::= SEQUENCE { messageID INTEGER, protocolOp CHOICE }
    public static byte[] buildLdapMessage(int messageId, byte[] protocolOp) {
        byte[] msgIdBytes = encodeInteger(messageId);
        byte[] content    = concat(msgIdBytes, protocolOp);
        return encodeSequence(content);
    }

    // ----------------------------------------------------------------
    // BUILD BIND REQUEST (RFC 4511 Section 4.2)
    // BindRequest ::= [APPLICATION 0] SEQUENCE {
    //     version  INTEGER (1..127),
    //     name     LDAPDN,
    //     authentication AuthenticationChoice
    // }
    // ----------------------------------------------------------------
    public static byte[] buildBindRequest(int messageId, 
                                          String bindDN, 
                                          String password) {
        byte[] version    = encodeInteger(3); // LDAPv3
        byte[] name       = encodeOctetString(bindDN);
        byte[] auth       = encodeContextPrimitive(TAG_SIMPLE_AUTH, password);
        byte[] bindReqContent = concat(version, name, auth);
        byte[] bindReq    = encodeApplication(TAG_BIND_REQUEST, bindReqContent);
        return buildLdapMessage(messageId, bindReq);
    }

    // ----------------------------------------------------------------
    // BUILD ANONYMOUS BIND REQUEST (RFC 4511 Section 4.2)
    // Binds with empty DN and empty password
    // ----------------------------------------------------------------
    public static byte[] buildAnonymousBindRequest(int messageId) {
        return buildBindRequest(messageId, "", "");
    }

    // ----------------------------------------------------------------
    // BUILD SEARCH REQUEST (RFC 4511 Section 4.5)
    // SearchRequest ::= [APPLICATION 3] SEQUENCE {
    //     baseObject   LDAPDN,
    //     scope        ENUMERATED { baseObject(0), singleLevel(1), wholeSubtree(2) },
    //     derefAliases ENUMERATED { ... },
    //     sizeLimit    INTEGER,
    //     timeLimit    INTEGER,
    //     typesOnly    BOOLEAN,
    //     filter       Filter,
    //     attributes   AttributeSelection
    // }
    // ----------------------------------------------------------------
    public static byte[] buildSearchRequest(int messageId,
                                            String baseDN,
                                            String searchAttribute,
                                            String searchValue) {
        byte[] base         = encodeOctetString(baseDN);
        byte[] scope        = encodeEnumerated(2); // wholeSubtree
        byte[] derefAliases = encodeEnumerated(0); // neverDerefAliases
        byte[] sizeLimit    = encodeInteger(0);    // no limit
        byte[] timeLimit    = encodeInteger(0);    // no limit
        byte[] typesOnly    = encodeBoolean(false);

        // Build equality match filter: (cn=Ferrari SF90)
        // Filter ::= CHOICE { equalityMatch [3] AttributeValueAssertion }
        // AttributeValueAssertion ::= SEQUENCE { attributeDesc, assertionValue }
        byte[] attrDesc     = encodeOctetString(searchAttribute);
        byte[] assertValue  = encodeOctetString(searchValue);
        byte[] avaContent   = concat(attrDesc, assertValue);
        byte[] filter       = encodeTLV(TAG_EQUALITY_MATCH, avaContent);

        // Empty attributes list means return all attributes
        byte[] attributes   = encodeSequence(new byte[0]);

        byte[] searchContent = concat(base, scope, derefAliases,
                                      sizeLimit, timeLimit,
                                      typesOnly, filter, attributes);
        byte[] searchReq     = encodeApplication(TAG_SEARCH_REQUEST, searchContent);
        return buildLdapMessage(messageId, searchReq);
    }

    // ----------------------------------------------------------------
    // BUILD UNBIND REQUEST (RFC 4511 Section 4.3)
    // UnbindRequest ::= [APPLICATION 2] NULL
    // ----------------------------------------------------------------
    public static byte[] buildUnbindRequest(int messageId) {
        // Unbind is APPLICATION 2, primitive, with NULL content
        byte[] unbindReq = new byte[]{ (byte) TAG_UNBIND_REQUEST, 0x00 };
        return buildLdapMessage(messageId, unbindReq);
    }

    // ----------------------------------------------------------------
    // DEBUG HELPER — print bytes as hex for troubleshooting
    // ----------------------------------------------------------------
    public static String toHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02X ", b));
        }
        return sb.toString().trim();
    }
}