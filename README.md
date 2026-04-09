# COS332 Practical 5 - RFC 4511 Compliant LDAP Client

A hand-rolled LDAP client written in pure Java with **no external libraries**.  
All BER encoding and decoding is implemented from scratch in compliance with RFC 4511. Refer to prac 5 in the spec document. 

## Team Member

Uminathi Mdluli

Zamokuhle Zwane

## Project Structure

```
prac5/
├── LdapClient.java      # Main application - menu-driven CLI
├── LdapConnection.java  # TCP socket management, sends/receives LDAP packets
├── BerEncoder.java      # Encodes LDAP messages into BER byte arrays (RFC 4511)
├── BerDecoder.java      # Decodes BER byte arrays into Java objects
└── automobiles.ldif     # LDAP Data Interchange Format seed data
```
## MD5 Hash
For project submission 

MD5 - 917fa2f44646c0e9c7be2cbe97d0d295

```
RUN:

md5sum LdapClient.class

917fa2f44646c0e9c7be2cbe97d0d295  LdapClient.class
```

## To zip and unzip the tar
You must be careful to not md5sum that because the hash contains the date/timestamp of the zip. it'll change the md5.

```
To zip the file(this is for submission):
Must be in prac5 folder
tar -cvf ../prac5.tar *

To unzip the file directly in prac5/:
tar -xvf prac5.tar

// this is so we dont possibly overwrite our code
# 1. Create a folder to peek inside
mkdir test_view
# 2. Extract into that specific folder
tar -xvf prac5.tar -C test_view

```
## Prerequisites

| Requirement | Version |
|-------------|---------|
| Java (JDK)  | 11+     |
| OpenLDAP    | 2.4+    |

---

## Server Setup (Ubuntu / WSL)

### 1. Install OpenLDAP

```bash
sudo apt-get update
sudo apt-get install -y slapd ldap-utils
```

When prompted during installation:

| Prompt               | Value              |
|----------------------|--------------------|
| DNS domain name      | `COS332PRAC5`      |
| Organisation         | `COS332NETWORKS`   |
| Admin password       | `butter`           |

### 2. Reconfigure (if needed)

```bash
sudo dpkg-reconfigure slapd
```

Use the same values as above. At the end your base DN will be:

```
dc=COS332PRAC5,dc=com
```

### 3. Start the server

```bash
sudo service slapd start

# Verify port 389 is open
sudo ss -tlnp | grep 389
```

---

## Loading the Directory Data

### Create the LDIF file

```bash
cd ~/prac5
nano automobiles.ldif
```

Paste the following content:

```ldif
# Automobiles organisational unit
dn: ou=Automobiles,dc=COS332PRAC5,dc=com
objectClass: top
objectClass: organizationalUnit
ou: Automobiles

# Ferrari SF90
dn: cn=Ferrari SF90,ou=Automobiles,dc=COS332PRAC5,dc=com
objectClass: top
objectClass: device
cn: Ferrari SF90
description: 340

# Bugatti Chiron
dn: cn=Bugatti Chiron,ou=Automobiles,dc=COS332PRAC5,dc=com
objectClass: top
objectClass: device
cn: Bugatti Chiron
description: 420

# Lamborghini Huracan
dn: cn=Lamborghini Huracan,ou=Automobiles,dc=COS332PRAC5,dc=com
objectClass: top
objectClass: device
cn: Lamborghini Huracan
description: 325

# Porsche 911 GT3
dn: cn=Porsche 911 GT3,ou=Automobiles,dc=COS332PRAC5,dc=com
objectClass: top
objectClass: device
cn: Porsche 911 GT3
description: 318

# McLaren P1
dn: cn=McLaren P1,ou=Automobiles,dc=COS332PRAC5,dc=com
objectClass: top
objectClass: device
cn: McLaren P1
description: 350
```

### Import into OpenLDAP

```bash
ldapadd -x -H ldap://localhost \
        -D "cn=admin,dc=COS332PRAC5,dc=com" \
        -W \
        -f automobiles.ldif
```

### Verify the data loaded

```bash
ldapsearch -x \
           -D "cn=admin,dc=COS332PRAC5,dc=com" \
           -w butter \
           -b "ou=Automobiles,dc=COS332PRAC5,dc=com" \
           "(objectClass=device)"
```


## Directory Information Tree (DIT)

```
dc=COS332PRAC5,dc=com
└── ou=Automobiles
    ├── cn=Ferrari SF90        description: 340
    ├── cn=Bugatti Chiron      description: 420
    ├── cn=Lamborghini Huracan description: 325
    ├── cn=Porsche 911 GT3     description: 318
    └── cn=McLaren P1          description: 350
```


## Compile and Run

```bash
cd ~/prac5
javac *.java
java LdapClient
```


## Menu Options

| Option | Operation | RFC 4511 Section |
|--------|-----------|-----------------|
| 1 | Search by name (equalityMatch filter) | §4.5.1 |
| 2 | List all automobiles | §4.5 |
| 3 | Filter by speed - **client-side** | §4.5 |
| 4 | Filter by speed - **server-side** `>=` | §4.5.1 |
| 5 | Add a new automobile | §4.7 AddRequest |
| 6 | Delete an automobile | §4.8 DelRequest |
| 7 | Modify an automobile's max speed | §4.6 ModifyRequest |
| 8 | Exit (sends UnbindRequest) | §4.3 |


## BER Encoding Reference

Every LDAP message is a BER-encoded packet with the structure:

```
LDAPMessage ::= SEQUENCE {
    messageID   MessageID,
    protocolOp  CHOICE {
        bindRequest     BindRequest,
        bindResponse    BindResponse,
        searchRequest   SearchRequest,
        ...
    }
}
```

On the wire this looks like:

30          -- Tag: SEQUENCE (0x30)
[length]    -- Total length of what follows
02 01 [id]  -- INTEGER: message ID
[op tag]    -- Tag identifying which operation
[op length] -- Length of operation data
[op data]   -- The actual operation data
```

### Universal BER Tags

| Tag  | Type        |
|------|-------------|
| 0x01 | BOOLEAN     |
| 0x02 | INTEGER     |
| 0x04 | OCTET STRING (strings in LDAP) |
| 0x0A | ENUMERATED  |
| 0x30 | SEQUENCE    |
| 0x31 | SET         |

### LDAP Application Tags (RFC 4511 §4)

| Tag  | Operation              |
|------|------------------------|
| 0x60 | BindRequest  [APP 0]   |
| 0x61 | BindResponse [APP 1]   |
| 0x42 | UnbindRequest [APP 2] (primitive) |
| 0x63 | SearchRequest [APP 3]  |
| 0x64 | SearchResultEntry [APP 4] |
| 0x65 | SearchResultDone [APP 5] |
| 0x66 | ModifyRequest [APP 6]  |
| 0x67 | ModifyResponse [APP 7] |
| 0x68 | AddRequest [APP 8]     |
| 0x69 | AddResponse [APP 9]    |
| 0x4A | DelRequest [APP 10] (primitive) |
| 0x6B | DelResponse [APP 11]   |

### Context-Specific Tags (Filters)

| Tag  | Meaning                           |
|------|-----------------------------------|
| 0x80 | SimpleAuthentication (password)   |
| 0xA3 | equalityMatch filter  [CTX 3]     |
| 0xA5 | greaterOrEqual filter [CTX 5]     |

### BindRequest Wire Format

```
60 [len]               -- BindRequest tag
  02 01 03             -- INTEGER: LDAP version 3
  04 [len] [DN bytes]  -- OCTET STRING: bind DN
  80 [len] [pw bytes]  -- [0] PRIMITIVE: simple password
```

## Notes on Server-Side Speed Filtering (Option 4)

The `description` attribute uses the `caseIgnoreString` (DirectoryString) syntax in OpenLDAP, so the `>=` comparison is **lexicographic**, not numeric.

Speed values are zero-padded to **3 digits** (e.g. `340`, `042`) so that lexicographic order matches numeric order for the range 000–999 km/h used in this directory.

For a fully correct numeric comparison a custom schema with `INTEGER` syntax would be required. This trade-off is documented to demonstrate understanding of RFC 4511 §4.5.1 and RFC 4512 (LDAP models / attribute syntax).


## ldap-utils Command Reference

The `ldap-utils` package ships a set of command-line tools that talk directly to the LDAP server. They are useful for seeding data, debugging, and verifying what is in the directory independently of your Java client.

### Common Flags

| Flag | Meaning |
|------|---------|
| `-x` | Simple authentication (no SASL) |
| `-H ldap://localhost` | Server URI (alternative to `-h`/`-p`) |
| `-D "cn=admin,..."` | Bind DN - who you are logging in as |
| `-w butter` | Password inline (use `-W` to be prompted instead) |
| `-b "ou=..."` | Base DN - where in the tree to start the operation |
| `-f file.ldif` | Read operations from an LDIF file |


### ldapadd - Add entries from an LDIF file

Reads an LDIF file and sends an **AddRequest** (RFC 4511 §4.7) for each entry block.

```bash
ldapadd -x -H ldap://localhost \
        -D "cn=admin,dc=COS332PRAC5,dc=com" \
        -w butter \
        -f automobiles.ldif
```

Each blank-line-separated block in the LDIF becomes one directory entry. The `dn:` line sets the Distinguished Name; every line below it is an attribute. If the entry already exists you will get error code **68 (entryAlreadyExists)** - delete it first or use `ldapmodify` instead.


### ldapmodify - Modify or add entries

Used to change existing entries. The LDIF must include a `changetype:` directive:

```bash
ldapmodify -x -H ldap://localhost \
           -D "cn=admin,dc=COS332PRAC5,dc=com" \
           -w butter << 'EOF'
dn: cn=Ferrari SF90,ou=Automobiles,dc=COS332PRAC5,dc=com
changetype: modify
replace: description
description: 360
EOF
```

| `changetype` value | Effect |
|--------------------|--------|
| `add`      | Add a new entry (same as `ldapadd`) |
| `modify`   | Change attributes on an existing entry |
| `delete`   | Delete the entry |
| `modrdn`   | Rename the entry |

Inside a `changetype: modify` block, each change starts with `add:`, `replace:`, or `delete:` followed by the attribute name, then the new value, then a `-` separator line.


### ldapdelete - Delete an entry by DN

```bash
ldapdelete -x -H ldap://localhost \
           -D "cn=admin,dc=COS332PRAC5,dc=com" \
           -w butter \
           "cn=Ferrari SF90,ou=Automobiles,dc=COS332PRAC5,dc=com"
```

The DN is passed as a positional argument. The server sends back a **DelResponse** (RFC 4511 §4.8). Error code **32 (noSuchObject)** means the DN does not exist.


### ldapsearch - Search the directory

```bash
ldapsearch -x -H ldap://localhost \
           -D "cn=admin,dc=COS332PRAC5,dc=com" \
           -w butter \
           -b "ou=Automobiles,dc=COS332PRAC5,dc=com" \
           "(objectClass=device)"
```

The last argument is the **search filter** in RFC 4515 string notation. Common examples:

| Filter | Matches |
|--------|---------|
| `(objectClass=device)` | All device entries |
| `(cn=Ferrari SF90)` | Exact name match |
| `(description>=300)` | Speed >= 300 (lexicographic) |
| `(&(objectClass=device)(description>=300))` | Both conditions (AND) |

By default `ldapsearch` returns all attributes. You can restrict this by listing attribute names after the filter:

```bash
# Return only cn and description
ldapsearch ... "(objectClass=device)" cn description
```

### Resetting the Admin Password

If `ldap_bind: Invalid credentials (49)` is returned, the admin password does not match. Reset it without knowing the current password by authenticating over the Unix socket as root:

```bash
# Step 1 - generate a salted SHA hash of the new password
sudo slappasswd -s butter
# Output looks like: {SSHA}abc123...

# Step 2 - write the new hash directly to the config database
sudo ldapmodify -Y EXTERNAL -H ldapi:/// << 'EOF'
dn: olcDatabase={1}mdb,cn=config
changetype: modify
replace: olcRootPW
olcRootPW: {SSHA}abc123...
EOF

sudo service slapd restart
```

`-Y EXTERNAL` uses the OS-level identity (root) instead of a password, bypassing the broken credential entirely. After the restart `ldapadd -w butter` should work.

## Bonus Features

For the bonus features, we focused on full protocol compliance.

### **BerEncoder** -add buildAddRequest, buildDeleteRequest, buildModifyRequest, buildGreaterOrEqualFilter (replaces the equality match filter in a new search overload).

In the BerEncoder, we implemented the Add, Delete, and Modify request builders.

### **BerDecoder**  -add response tag constants and decode handlers for AddResponse (0x69), DeleteResponse (0x6B), ModifyResponse (0x67).

A key technical detail we'd like to highlight is the DeleteRequest; unlike other sequences, it’s encoded as a primitive type where the DN is the direct value. We also unified the BerDecoder—since Add, Delete, and Modify all return an LDAPResult, we reused our existing decoding logic to keep the codebase DRY (Don't Repeat Yourself).

### **LdapConnection**  -add add(), delete(), modify(), searchGreaterOrEqual() methods.

### **LdapClient**  -add menu options 5/6/7/8 for each feature.

We added a GreaterOrEqual filter, which uses the AttributeValueAssertion structure.

You'll notice in our demo that when we search for values between 100 and 999 km/h, the client zero-pads the input. This is a deliberate design choice: since the LDAP directory stores these as strings, we perform this normalization so that the server's lexicographic comparison behaves like a numeric comparison.

It shows we're accounting for the underlying LDAP Data Schema.

To keep the implementation clean, we refactored search() to extract collectSearchResults(). 

This allowed our new searchGreaterOrEqual() method to reuse the result-collection loop without duplicating the logic for handling multiple search result entries followed by a 'SearchDone' packet.




## References
- [RFC 4511](https://datatracker.ietf.org/doc/html/rfc4511) - Lightweight Directory Access Protocol (LDAP): The Protocol  
- [RFC 4512](https://datatracker.ietf.org/doc/html/rfc4512) - LDAP: Directory Information Models  
- [RFC 4510](https://datatracker.ietf.org/doc/html/rfc4510) - LDAP: Technical Specification Road Map
