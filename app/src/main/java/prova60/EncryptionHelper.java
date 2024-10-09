package prova60;

import javax.crypto.Cipher;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;
import java.util.Base64;

public class EncryptionHelper {

    public static SecretKeySpec deriveKeyPbkdf2(byte[] salt, String password) {
        try {
            int iterations = 1000;
            int keyLength = 256;
            SecretKeyFactory secretKeyFactory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
            PBEKeySpec pbeKeySpec = new PBEKeySpec(password.toCharArray(), salt, iterations, keyLength);
            SecretKey secretKey = secretKeyFactory.generateSecret(pbeKeySpec);
            return new SecretKeySpec(secretKey.getEncoded(), "AES");
        } catch (Exception e) {
            throw new RuntimeException("Error during key generation", e);
        }
    }

    public static String encrypt(String data, String password) throws Exception {
        SecureRandom random = new SecureRandom();
        byte[] salt = new byte[16];
        random.nextBytes(salt);

        SecretKeySpec secretKeySpec = deriveKeyPbkdf2(salt, password);

        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec);
        byte[] iv = cipher.getIV();
        byte[] encryptedData = cipher.doFinal(data.getBytes("UTF-8"));

        String encodedIV = Base64.getEncoder().encodeToString(iv);
        String encodedSalt = Base64.getEncoder().encodeToString(salt);
        String encodedEncryptedData = Base64.getEncoder().encodeToString(encryptedData);

        return encodedIV + ":" + encodedSalt + ":" + encodedEncryptedData;
    }

    public static String decrypt(String encryptedData, String password) throws Exception {
        String[] parts = encryptedData.split(":");
        byte[] iv = Base64.getDecoder().decode(parts[0]);
        byte[] salt = Base64.getDecoder().decode(parts[1]);
        byte[] data = Base64.getDecoder().decode(parts[2]);

        SecretKeySpec secretKeySpec = deriveKeyPbkdf2(salt, password);

        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, new javax.crypto.spec.IvParameterSpec(iv));
        byte[] decryptedData = cipher.doFinal(data);

        return new String(decryptedData, "UTF-8");
    }

    public static void main(String[] args) {
        try {
            String originalData = "Hello World!";
            String password = "strong_password";

            String encrypted = encrypt(originalData, password);
            System.out.println("Encrypted: " + encrypted);

            String decrypted = decrypt(encrypted, password);
            System.out.println("Decrypted: " + decrypted);

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
