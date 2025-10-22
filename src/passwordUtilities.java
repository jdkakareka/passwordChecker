import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.util.HashSet;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.util.Base64;
import java.util.Scanner;

public class passwordUtilities {

    private static final int PBKDF2_ITERATIONS = 1767170;
    private static final int SALT_BYTE_SIZE = 16;
    private static final int HASH_BYTE_SIZE = 256;
    private static final String HASH_ALGORITHM = "PBKDF2WithHmacSHA256";
    private static final String SPECIAL_CHARACTERS = "!@#$%^&*()_+-=[]{}|;':\",./<>?";

    /**
     * Checks if a password meets the strength requirements.
     *
     * @param password The password to check.
     * @param passwords A set of common passwords to check against.
     * @return A string indicating the strength of the password.
     */
    public static String passwordChecker(String password, HashSet<String> passwords) {

        if (passwords.contains(password)) {
            return "Your password meets all the requirements but is fairly common!";
        }

        if (password.length() < 8) {
            return "Your password is too short!";
        }

        boolean hasSpecialCharacter = false;
        boolean hasNumber = false;

        for (char c : password.toCharArray()) {
            if (SPECIAL_CHARACTERS.indexOf(c) >= 0) {
                hasSpecialCharacter = true;
            } else if (Character.isDigit(c)) {
                hasNumber = true;
            }
        }

        if (!hasSpecialCharacter) {
            return "Your password is missing a special character!";
        }
        if (!hasNumber) {
            return "Your password is missing a number!";
        }

        return "Your password is strong and not common!";
    }

    /**
     * Parses a file of passwords and returns them as a HashSet.
     *
     * @param size The size of the password list to use (1 for 10k, 2 for 10 million).
     * @return A HashSet containing the passwords.
     */
    public static HashSet<String> parser(int size){
        String filePath2 = "src/10_million_password_list_top_1000000.txt";
        String filePath1 = "src/10k-most-common.txt";
        HashSet<String> passwordsTenK = new HashSet<>();
        HashSet<String> passwordsTenMil = new HashSet<>();

        if(size == 1) {
            try (BufferedReader br = new BufferedReader(new FileReader(filePath1))) {
                long startTime = System.currentTimeMillis();
                String line;
                while ((line = br.readLine()) != null) {
                    passwordsTenK.add(line.trim());
                }
                long endTime = System.currentTimeMillis();
                long duration = endTime - startTime;
                System.out.println("Time to write 10k passwords (m/s): " + duration);
                return passwordsTenK;
            } catch (IOException e) {
                System.err.println("Error reading file: " + e.getMessage());
                return new HashSet<>();
            }
        }
        if(size == 2) {
            try (BufferedReader br = new BufferedReader(new FileReader(filePath2))) {
                long startTime = System.currentTimeMillis();
                String line;
                while ((line = br.readLine()) != null) {
                    passwordsTenMil.add(line.trim());
                }
                long endTime = System.currentTimeMillis();
                long duration = endTime - startTime;
                System.out.println("Time to write 10 million passwords (m/s): " + duration);
                return passwordsTenMil;
            } catch (IOException e) {
                System.err.println("Error reading file: " + e.getMessage());
                return new HashSet<>();
            }
        }
        else{
            System.out.println("Please listen to instructions");
        }

        return passwordsTenK;
    }

    /**Hashes a plaintext password using PBKDF2 with HMAC-SHA256.
     * This method generates a unique salt for each password, ensuring that
     * identical passwords result in different hashes, which helps protect
     * against table attacks.
     *
     * @param password - Password being hashed
     * @return the hashed password - Base64-Encoded(salt$password)
     */

    public static String hashPassword(String password) {
        try {
            SecureRandom random = new SecureRandom();
            byte[] salt = new byte[SALT_BYTE_SIZE];
            random.nextBytes(salt);
            KeySpec spec = new PBEKeySpec(password.toCharArray(), salt, PBKDF2_ITERATIONS, HASH_BYTE_SIZE);
            SecretKeyFactory factory = SecretKeyFactory.getInstance(HASH_ALGORITHM);
            byte[] hash = factory.generateSecret(spec).getEncoded();
            return Base64.getEncoder().encodeToString(salt) + "$" + Base64.getEncoder().encodeToString(hash);

        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * Decodes the storedHash, splitting the salt and the hash, storing both, then hashes the password attempt.
     * It then attaches the same salt as the storedHash to the hashed password, and simply checks if the hash arrays are equal
     *
     * @param passwordAttempt - Password Attempt (Think of this as a login attempt)
     * @param storedHash - Password Hash of correct password (Password made when user signed up)
     * @return True or False based on if the passwords are the same
     */

    public static boolean verifyPassword(String passwordAttempt, String storedHash){
        try {
            String[] parts = storedHash.split("\\$");
            byte[] salt = Base64.getDecoder().decode(parts[0]);
            byte[] originalHash = Base64.getDecoder().decode(parts[1]);

            KeySpec spec = new PBEKeySpec(passwordAttempt.toCharArray(), salt, PBKDF2_ITERATIONS, HASH_BYTE_SIZE);
            SecretKeyFactory factory = SecretKeyFactory.getInstance(HASH_ALGORITHM);
            byte[] attemptHash = factory.generateSecret(spec).getEncoded();
            return java.util.Arrays.equals(originalHash, attemptHash);

        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new RuntimeException(e);
        }

    }

    /**
     * The main method of the program.
     *
     * @param args The command line arguments.
     */
        public static void main(String[] args) {
            // Parses through a set list of passwords adding them to a HashMap
            // Size: 1 = 10k Passwords
            // Size: 2 = 10 Million Passwords */
        HashSet<String> commonPasswords = parser(2);


        System.out.println("Hey! What would you like to do? \n " +
                "1. Check if my password is strong. \n " +
                "2. Hash a Password \n" +
                "3. Verify a Password (Checks if Hash and Password Match");
        Scanner scanner = new Scanner(System.in);
        System.out.println("Enter a Choice: ");
        String choice = scanner.nextLine();

        switch (choice) {

            case "1":{
                System.out.println("Enter a Password: ");
                String password = scanner.nextLine();
                System.out.println(passwordChecker(password,commonPasswords));
                break;
            }
            case "2":{
                System.out.println("Enter a Password: ");
                String password = scanner.nextLine();
                System.out.println(hashPassword(password));
                break;
            }
            case "3":{
                System.out.println("Enter a Password: ");
                String password = scanner.nextLine();
                System.out.println("Enter a Hash: ");
                String hash = scanner.nextLine();
                System.out.println(verifyPassword(password,hash));
                break;
            }
        }







    }
}
