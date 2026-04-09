import java.util.List;
import java.util.Scanner;

public class LdapClient {

    // ----------------------------------------------------------------
    // LDAP SERVER CONFIGURATION
    // ----------------------------------------------------------------
    private static final String LDAP_HOST  = "127.0.0.1";
    private static final int    LDAP_PORT  = 389;
    private static final String BASE_DN    = "ou=Automobiles,dc=COS332PRAC5,dc=com";
    private static final String BIND_DN    = "cn=admin,dc=COS332PRAC5,dc=com";
    private static final String BIND_PASS  = "butter";

    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);
        printBanner();

        boolean running = true;
        while (running) {
            printMenu();
            System.out.print("Enter choice: ");
            String choice = scanner.nextLine().trim();

            switch (choice) {
                case "1": searchByName(scanner);          break;
                case "2": listAllAutomobiles();           break;
                case "3": searchBySpeedClientSide(scanner); break;
                case "4": searchBySpeedServerSide(scanner); break;
                case "5": addAutomobile(scanner);         break;
                case "6": deleteAutomobile(scanner);      break;
                case "7": modifySpeed(scanner);           break;
                case "8":
                    running = false;
                    System.out.println("\nGoodbye!");
                    break;
                default:
                    System.out.println("Invalid choice. Please try again.");
            }
        }

        scanner.close();
    }

    // ----------------------------------------------------------------
    // PRINT BANNER
    // ----------------------------------------------------------------
    private static void printBanner() {
        System.out.println("╔════════════════════════════════════════════╗");
        System.out.println("║     AUTOMOBILE LDAP DIRECTORY CLIENT       ║");
        System.out.println("║     COS332 Practical 5                     ║");
        System.out.println("║     RFC 4511 Compliant LDAP Client         ║");
        System.out.println("╚════════════════════════════════════════════╝");
        System.out.println();
        System.out.println("Server : " + LDAP_HOST + ":" + LDAP_PORT);
        System.out.println("Base DN: " + BASE_DN);
        System.out.println();
    }

    // ----------------------------------------------------------------
    // PRINT MENU
    // ----------------------------------------------------------------
    private static void printMenu() {
        System.out.println("┌──────────────────────────────────────────────┐");
        System.out.println("│  MENU                                        │");
        System.out.println("│  1. Search automobile by name                │");
        System.out.println("│  2. List all automobiles                     │");
        System.out.println("│  3. Search by max speed (client-side filter) │");
        System.out.println("│  4. Search by max speed (server-side >=)     │");
        System.out.println("│  5. Add new automobile                       │");
        System.out.println("│  6. Delete an automobile                     │");
        System.out.println("│  7. Modify an automobile's max speed         │");
        System.out.println("│  8. Exit                                     │");
        System.out.println("└──────────────────────────────────────────────┘");
    }

    // ----------------------------------------------------------------
    // 1. SEARCH BY NAME
    // ----------------------------------------------------------------
    private static void searchByName(Scanner scanner) {
        System.out.print("\nEnter automobile name: ");
        String name = scanner.nextLine().trim();
        if (name.isEmpty()) { System.out.println("Name cannot be empty."); return; }

        LdapConnection conn = new LdapConnection(LDAP_HOST, LDAP_PORT);
        try {
            conn.connect();
            if (!conn.bind(BIND_DN, BIND_PASS)) {
                System.out.println("ERROR: Could not authenticate to LDAP server.");
                return;
            }

            List<BerDecoder.LdapEntry> entries = conn.search(BASE_DN, "cn", name);

            System.out.println();
            System.out.println("══════════════════════════════════════");
            if (entries.isEmpty()) {
                System.out.println("No automobile found with name: " + name);
            } else {
                for (BerDecoder.LdapEntry entry : entries) {
                    String speed = entry.getAttributeValue("description");
                    System.out.println("Automobile : " + name);
                    System.out.println("DN         : " + entry.dn);
                    System.out.println("Max Speed  : " +
                        (speed != null ? speed + " km/h" : "not recorded"));
                    System.out.println("Attributes :");
                    for (BerDecoder.LdapAttribute attr : entry.attributes) {
                        for (String val : attr.values) {
                            System.out.println("  " + attr.name + ": " + val);
                        }
                    }
                }
            }
            System.out.println("══════════════════════════════════════");

        } catch (Exception e) {
            System.out.println("ERROR: " + e.getMessage());
            e.printStackTrace();
        } finally {
            try { conn.disconnect(); } catch (Exception ignored) {}
        }
        System.out.println();
    }

    // ----------------------------------------------------------------
    // 2. LIST ALL AUTOMOBILES
    // ----------------------------------------------------------------
    private static void listAllAutomobiles() {
        LdapConnection conn = new LdapConnection(LDAP_HOST, LDAP_PORT);
        try {
            conn.connect();
            if (!conn.bind(BIND_DN, BIND_PASS)) {
                System.out.println("ERROR: Could not authenticate to LDAP server.");
                return;
            }

            List<BerDecoder.LdapEntry> entries = conn.search(BASE_DN, "objectClass", "device");

            System.out.println();
            System.out.println("══════════════════════════════════════");
            System.out.println("  ALL AUTOMOBILES IN DIRECTORY");
            System.out.println("══════════════════════════════════════");

            if (entries.isEmpty()) {
                System.out.println("No automobiles found in directory.");
            } else {
                System.out.printf("  %-25s %s%n", "NAME", "MAX SPEED (km/h)");
                System.out.println("  " + "─".repeat(38));
                for (BerDecoder.LdapEntry entry : entries) {
                    String carName = entry.getAttributeValue("cn");
                    String speed   = entry.getAttributeValue("description");
                    System.out.printf("  %-25s %s%n",
                        carName != null ? carName : "unknown",
                        speed   != null ? speed + " km/h" : "N/A");
                }
                System.out.println("  " + "─".repeat(38));
                System.out.println("  Total: " + entries.size() + " automobile(s)");
            }
            System.out.println("══════════════════════════════════════");

        } catch (Exception e) {
            System.out.println("ERROR: " + e.getMessage());
            e.printStackTrace();
        } finally {
            try { conn.disconnect(); } catch (Exception ignored) {}
        }
        System.out.println();
    }

    // ----------------------------------------------------------------
    // 3. SEARCH BY SPEED — client-side filtering (original)
    // ----------------------------------------------------------------
    private static void searchBySpeedClientSide(Scanner scanner) {
        System.out.print("\nShow automobiles faster than (km/h): ");
        int minSpeed;
        try { minSpeed = Integer.parseInt(scanner.nextLine().trim()); }
        catch (NumberFormatException e) { System.out.println("Please enter a valid number."); return; }

        LdapConnection conn = new LdapConnection(LDAP_HOST, LDAP_PORT);
        try {
            conn.connect();
            if (!conn.bind(BIND_DN, BIND_PASS)) {
                System.out.println("ERROR: Could not authenticate to LDAP server.");
                return;
            }

            List<BerDecoder.LdapEntry> entries = conn.search(BASE_DN, "objectClass", "device");
            printSpeedResults(entries, minSpeed, "(client-side filter)");

        } catch (Exception e) {
            System.out.println("ERROR: " + e.getMessage());
            e.printStackTrace();
        } finally {
            try { conn.disconnect(); } catch (Exception ignored) {}
        }
        System.out.println();
    }

    // ----------------------------------------------------------------
    // 4. SEARCH BY SPEED — server-side greaterOrEqual filter (RFC 4511)
    //
    // Uses the LDAP greaterOrEqual filter [5] (tag 0xA5) defined in
    // RFC 4511 Section 4.5.1.  The server evaluates the filter before
    // sending results, so only matching entries travel over the wire.
    //
    // NOTE FOR DEMO: OpenLDAP stores 'description' with the
    // caseIgnoreString (DirectoryString) syntax, which means the >=
    // comparison is lexicographic, not numeric.  Speeds must therefore
    // be zero-padded to the same number of digits for correct ordering
    // (e.g. "300" not "300", "420", "325" → lexicographic order is
    // "325" > "320" but "42" > "325" because '4' > '3').
    // Our LDIF already uses 3-digit values, so results are correct for
    // speeds 100–999.  For a fully correct numeric comparison one would
    // use a custom schema with INTEGER syntax.  We document this
    // trade-off to demonstrate understanding of RFC 4511 §4.5.1 and
    // RFC 4512 (LDAP models / attribute syntax).
    // ----------------------------------------------------------------
    private static void searchBySpeedServerSide(Scanner scanner) {
        System.out.print("\nShow automobiles with max speed >= (km/h): ");
        String input = scanner.nextLine().trim();
        int minSpeed;
        try { minSpeed = Integer.parseInt(input); }
        catch (NumberFormatException e) { System.out.println("Please enter a valid number."); return; }

        // Zero-pad to 3 digits so lexicographic >= matches numeric >=
        // for the speed range used in our directory (100–999 km/h)
        String paddedValue = String.format("%03d", minSpeed);

        LdapConnection conn = new LdapConnection(LDAP_HOST, LDAP_PORT);
        try {
            conn.connect();
            if (!conn.bind(BIND_DN, BIND_PASS)) {
                System.out.println("ERROR: Could not authenticate to LDAP server.");
                return;
            }

            // Server evaluates (description >= paddedValue) — only
            // matching entries are returned across the wire
            List<BerDecoder.LdapEntry> entries =
                conn.searchGreaterOrEqual(BASE_DN, "description", paddedValue);

            printSpeedResults(entries, minSpeed - 1, "(server-side >= filter, RFC 4511 §4.5.1)");

        } catch (Exception e) {
            System.out.println("ERROR: " + e.getMessage());
            e.printStackTrace();
        } finally {
            try { conn.disconnect(); } catch (Exception ignored) {}
        }
        System.out.println();
    }

    // ----------------------------------------------------------------
    // 5. ADD AUTOMOBILE (RFC 4511 Section 4.7 — AddRequest)
    // ----------------------------------------------------------------
    private static void addAutomobile(Scanner scanner) {
        System.out.print("\nEnter new automobile name (cn): ");
        String name = scanner.nextLine().trim();
        if (name.isEmpty()) { System.out.println("Name cannot be empty."); return; }

        System.out.print("Enter max speed in km/h: ");
        String speedStr = scanner.nextLine().trim();
        int speed;
        try { speed = Integer.parseInt(speedStr); }
        catch (NumberFormatException e) { System.out.println("Please enter a valid number."); return; }

        // Build the DN for the new entry
        String entryDN = "cn=" + name + "," + BASE_DN;

        // Build attribute list:
        // objectClass: top (required by OpenLDAP schema)
        // objectClass: device (our chosen structural class)
        // cn:          the automobile name
        // description: the max speed as a string
        String[][] attributes = {
            { "objectClass", "top", "device" },
            { "cn",          name             },
            { "description", String.format("%03d", speed) }
        };

        LdapConnection conn = new LdapConnection(LDAP_HOST, LDAP_PORT);
        try {
            conn.connect();
            if (!conn.bind(BIND_DN, BIND_PASS)) {
                System.out.println("ERROR: Could not authenticate to LDAP server.");
                return;
            }

            System.out.println();
            boolean ok = conn.add(entryDN, attributes);
            System.out.println("══════════════════════════════════════");
            if (ok) {
                System.out.println("  Added: " + name + " (" + speed + " km/h)");
                System.out.println("  DN   : " + entryDN);
            } else {
                System.out.println("  Failed to add: " + name);
            }
            System.out.println("══════════════════════════════════════");

        } catch (Exception e) {
            System.out.println("ERROR: " + e.getMessage());
            e.printStackTrace();
        } finally {
            try { conn.disconnect(); } catch (Exception ignored) {}
        }
        System.out.println();
    }

    // ----------------------------------------------------------------
    // 6. DELETE AUTOMOBILE (RFC 4511 Section 4.8 — DelRequest)
    // ----------------------------------------------------------------
    private static void deleteAutomobile(Scanner scanner) {
        System.out.print("\nEnter automobile name to delete: ");
        String name = scanner.nextLine().trim();
        if (name.isEmpty()) { System.out.println("Name cannot be empty."); return; }

        String entryDN = "cn=" + name + "," + BASE_DN;

        LdapConnection conn = new LdapConnection(LDAP_HOST, LDAP_PORT);
        try {
            conn.connect();
            if (!conn.bind(BIND_DN, BIND_PASS)) {
                System.out.println("ERROR: Could not authenticate to LDAP server.");
                return;
            }

            System.out.println();
            System.out.print("Confirm delete of '" + name + "'? (yes/no): ");
            String confirm = scanner.nextLine().trim();
            if (!confirm.equalsIgnoreCase("yes")) {
                System.out.println("Delete cancelled.");
                return;
            }

            boolean ok = conn.delete(entryDN);
            System.out.println("══════════════════════════════════════");
            if (ok) {
                System.out.println("  Deleted: " + name);
                System.out.println("  DN     : " + entryDN);
            } else {
                System.out.println("  Failed to delete: " + name);
            }
            System.out.println("══════════════════════════════════════");

        } catch (Exception e) {
            System.out.println("ERROR: " + e.getMessage());
            e.printStackTrace();
        } finally {
            try { conn.disconnect(); } catch (Exception ignored) {}
        }
        System.out.println();
    }

    // ----------------------------------------------------------------
    // 7. MODIFY MAX SPEED (RFC 4511 Section 4.6 — ModifyRequest)
    // Uses the REPLACE operation so the new value overwrites the old.
    // ----------------------------------------------------------------
    private static void modifySpeed(Scanner scanner) {
        System.out.print("\nEnter automobile name to modify: ");
        String name = scanner.nextLine().trim();
        if (name.isEmpty()) { System.out.println("Name cannot be empty."); return; }

        System.out.print("Enter new max speed in km/h: ");
        String speedStr = scanner.nextLine().trim();
        int speed;
        try { speed = Integer.parseInt(speedStr); }
        catch (NumberFormatException e) { System.out.println("Please enter a valid number."); return; }

        String entryDN   = "cn=" + name + "," + BASE_DN;
        String newSpeed  = String.format("%03d", speed);

        LdapConnection conn = new LdapConnection(LDAP_HOST, LDAP_PORT);
        try {
            conn.connect();
            if (!conn.bind(BIND_DN, BIND_PASS)) {
                System.out.println("ERROR: Could not authenticate to LDAP server.");
                return;
            }

            // REPLACE overwrites the description attribute with the new speed
            boolean ok = conn.modify(
                entryDN,
                BerEncoder.MODIFY_OP_REPLACE,
                "description",
                new String[]{ newSpeed }
            );

            System.out.println();
            System.out.println("══════════════════════════════════════");
            if (ok) {
                System.out.println("  Modified: " + name);
                System.out.println("  New speed: " + speed + " km/h");
            } else {
                System.out.println("  Failed to modify: " + name);
            }
            System.out.println("══════════════════════════════════════");

        } catch (Exception e) {
            System.out.println("ERROR: " + e.getMessage());
            e.printStackTrace();
        } finally {
            try { conn.disconnect(); } catch (Exception ignored) {}
        }
        System.out.println();
    }

    // ----------------------------------------------------------------
    // SHARED SPEED RESULTS PRINTER
    // ----------------------------------------------------------------
    private static void printSpeedResults(List<BerDecoder.LdapEntry> entries,
                                          int minSpeed,
                                          String label) {
        System.out.println();
        System.out.println("══════════════════════════════════════");
        System.out.println("  AUTOMOBILES FASTER THAN " + minSpeed + " km/h " + label);
        System.out.println("══════════════════════════════════════");

        int count = 0;
        System.out.printf("  %-25s %s%n", "NAME", "MAX SPEED (km/h)");
        System.out.println("  " + "─".repeat(38));

        for (BerDecoder.LdapEntry entry : entries) {
            String carName  = entry.getAttributeValue("cn");
            String speedStr = entry.getAttributeValue("description");
            if (speedStr != null) {
                try {
                    int s = Integer.parseInt(speedStr.trim());
                    if (s > minSpeed) {
                        System.out.printf("  %-25s %d km/h%n",
                            carName != null ? carName : "unknown", s);
                        count++;
                    }
                } catch (NumberFormatException ignored) {}
            }
        }

        System.out.println("  " + "─".repeat(38));
        if (count == 0) {
            System.out.println("  No automobiles found faster than " + minSpeed + " km/h");
        } else {
            System.out.println("  Found: " + count + " automobile(s)");
        }
        System.out.println("══════════════════════════════════════");
    }
}