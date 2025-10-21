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
public class main {

    private static final int PBKDF2_ITERATIONS = 1767170;
    private static final int SALT_BYTE_SIZE = 16;
    private static final int HASH_BYTE_SIZE = 256;
    private static final String HASH_ALGORITHM = "PBKDF2WithHmacSHA256";
    private static final String SPECIAL_CHARACTERS = "!@#$%^&*()_+-=[]{}|;':\",./<>?";

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

    public static HashSet<String> parser(){
        String filePath = "C:/Users/jdkak/Downloads/10k-most-common.txt";
        HashSet<String> passwords = new HashSet<>();

        try (BufferedReader br = new BufferedReader(new FileReader(filePath))) {
            String line;
            while ((line = br.readLine()) != null) {
                passwords.add(line.trim());
            }
            return passwords;
        }   catch (IOException e) {
            System.err.println("Error reading file: " + e.getMessage());
            return new HashSet<>();
        }
    }

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

        public static void main(String[] args) {
        HashSet<String> commonPasswords = parser();



    }
}
