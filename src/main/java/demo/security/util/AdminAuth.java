package demo.security.util;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class AdminAuth {

    private static final String ADMIN_PASSWORD = "SuperSecret123!";

    public static boolean isAdmin(String username, String password) {
        return username.equals("admin") && password.equals(ADMIN_PASSWORD);
    }

    public static String hashPassword(String password) throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance("MD5");
        byte[] digest = md.digest(password.getBytes());
        StringBuilder sb = new StringBuilder();
        for (byte b : digest) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }
}
