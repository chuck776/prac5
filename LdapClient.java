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
                case "1":
                    searchByName(scanner);
                    break;
                case "2":
                    listAllAutomobiles();
                    break;
                case "3":
                    searchBySpeed(scanner);
                    break;
                case "4":
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
        System.out.println("╔════════════════════════════════════════╗");
        System.out.println("║     AUTOMOBILE LDAP DIRECTORY CLIENT   ║");
        System.out.println("║     COS332 Practical 5                 ║");
        System.out.println("║     RFC 4511 Compliant LDAP Client     ║");
        System.out.println("╚════════════════════════════════════════╝");
        System.out.println();
        System.out.println("Server : " + LDAP_HOST + ":" + LDAP_PORT);
        System.out.println("Base DN: " + BASE_DN);
        System.out.println();
    }

    // ----------------------------------------------------------------
    // PRINT MENU
    // ----------------------------------------------------------------
    private static void printMenu() {
        System.out.println("┌────────────────────────────────────────┐");
        System.out.println("│  MENU                                  │");
        System.out.println("│  1. Search automobile by name          │");
        System.out.println("│  2. List all automobiles               │");
        System.out.println("│  3. Search automobiles by max speed    │");
        System.out.println("│  4. Exit                               │");
        System.out.println("└────────────────────────────────────────┘");
    }

    // ----------------------------------------------------------------
    // SEARCH BY NAME
    // Asks user for asset name, queries LDAP, displays max speed
    // ----------------------------------------------------------------
    private static void searchByName(Scanner scanner) {
        System.out.print("\nEnter automobile name: ");
        String name = scanner.nextLine().trim();

        if (name.isEmpty()) {
            System.out.println("Name cannot be empty.");
            return;
        }

        LdapConnection conn = new LdapConnection(LDAP_HOST, LDAP_PORT);

        try {
            // Step 1 — Connect
            conn.connect();

            // Step 2 — Bind (authenticate)
            boolean bound = conn.bind(BIND_DN, BIND_PASS);
            if (!bound) {
                System.out.println("ERROR: Could not authenticate to LDAP server.");
                return;
            }

            // Step 3 — Search for the automobile by cn
            List<BerDecoder.LdapEntry> entries = conn.search(
                BASE_DN, "cn", name);

            // Step 4 — Display results
            System.out.println();
            System.out.println("══════════════════════════════════════");
            if (entries.isEmpty()) {
                System.out.println("No automobile found with name: " + name);
            } else {
                for (BerDecoder.LdapEntry entry : entries) {
                    String speed = entry.getAttributeValue("description");
                    System.out.println("Automobile : " + name);
                    System.out.println("DN         : " + entry.dn);
                    if (speed != null) {
                        System.out.println("Max Speed  : " + speed + " km/h");
                    } else {
                        System.out.println("Max Speed  : not recorded");
                    }
                    // Show all attributes
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
            // Step 5 — Unbind and disconnect
            try { conn.disconnect(); } catch (Exception e) {}
        }

        System.out.println();
    }

    // ----------------------------------------------------------------
    // LIST ALL AUTOMOBILES
    // Searches with cn=* to return all entries
    // ----------------------------------------------------------------
    private static void listAllAutomobiles() {
        LdapConnection conn = new LdapConnection(LDAP_HOST, LDAP_PORT);

        try {
            conn.connect();

            boolean bound = conn.bind(BIND_DN, BIND_PASS);
            if (!bound) {
                System.out.println("ERROR: Could not authenticate to LDAP server.");
                return;
            }

            // Search for all entries with any cn value
            List<BerDecoder.LdapEntry> entries = conn.search(
                BASE_DN, "objectClass", "device");

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
                        carName  != null ? carName  : "unknown",
                        speed    != null ? speed + " km/h" : "N/A");
                }
                System.out.println("  " + "─".repeat(38));
                System.out.println("  Total: " + entries.size() + " automobile(s)");
            }
            System.out.println("══════════════════════════════════════");

        } catch (Exception e) {
            System.out.println("ERROR: " + e.getMessage());
            e.printStackTrace();
        } finally {
            try { conn.disconnect(); } catch (Exception e) {}
        }

        System.out.println();
    }

    // ----------------------------------------------------------------
    // SEARCH BY SPEED
    // Lists all automobiles faster than a given speed
    // Demonstrates client-side filtering of LDAP results
    // ----------------------------------------------------------------
    private static void searchBySpeed(Scanner scanner) {
        System.out.print("\nShow automobiles faster than (km/h): ");
        String input = scanner.nextLine().trim();

        int minSpeed;
        try {
            minSpeed = Integer.parseInt(input);
        } catch (NumberFormatException e) {
            System.out.println("Please enter a valid number.");
            return;
        }

        LdapConnection conn = new LdapConnection(LDAP_HOST, LDAP_PORT);

        try {
            conn.connect();

            boolean bound = conn.bind(BIND_DN, BIND_PASS);
            if (!bound) {
                System.out.println("ERROR: Could not authenticate to LDAP server.");
                return;
            }

            // Fetch all automobiles then filter client side
            List<BerDecoder.LdapEntry> entries = conn.search(
                BASE_DN, "objectClass", "device");

            System.out.println();
            System.out.println("══════════════════════════════════════");
            System.out.println("  AUTOMOBILES FASTER THAN " +
                minSpeed + " km/h");
            System.out.println("══════════════════════════════════════");

            int count = 0;
            System.out.printf("  %-25s %s%n", "NAME", "MAX SPEED (km/h)");
            System.out.println("  " + "─".repeat(38));

            for (BerDecoder.LdapEntry entry : entries) {
                String carName = entry.getAttributeValue("cn");
                String speedStr = entry.getAttributeValue("description");

                if (speedStr != null) {
                    try {
                        int speed = Integer.parseInt(speedStr.trim());
                        if (speed >= minSpeed) {
                            System.out.printf("  %-25s %d km/h%n",
                                carName != null ? carName : "unknown", speed);
                            count++;
                        }
                    } catch (NumberFormatException e) {
                        // Skip entries with non-numeric speed
                    }
                }
            }

            System.out.println("  " + "─".repeat(38));
            if (count == 0) {
                System.out.println("  No automobiles found faster than " +
                    minSpeed + " km/h");
            } else {
                System.out.println("  Found: " + count + " automobile(s)");
            }
            System.out.println("══════════════════════════════════════");

        } catch (Exception e) {
            System.out.println("ERROR: " + e.getMessage());
            e.printStackTrace();
        } finally {
            try { conn.disconnect(); } catch (Exception e) {}
        }

        System.out.println();
    }
}