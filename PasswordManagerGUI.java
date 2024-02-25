import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.*;
import java.security.spec.KeySpec;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;
import java.util.Base64;

public class PasswordManagerGUI extends JFrame implements ActionListener {

    private static final String SECRET_KEY_ALGORITHM = "AES";
    private static final String CIPHER_ALGORITHM = "AES/CBC/PKCS5Padding";
    private static final int KEY_LENGTH = 256;
    private static final int SALT_LENGTH = 16;
    private static final int ITERATIONS = 65536;
    private static final int IV_LENGTH = 16;
    private static final String ENCRYPTED_PASSWORD_FILE = "encrypted_password.txt";

    private JTextField masterPasswordField, passwordField, encryptedPasswordField, decryptedPasswordField;

    public PasswordManagerGUI() {
        setTitle("Password Manager");
        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        setSize(400, 300);
        setLocationRelativeTo(null);

        JPanel mainPanel = new JPanel();
        mainPanel.setLayout(new GridLayout(5, 2, 10, 10));
        mainPanel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));

        JLabel masterPasswordLabel = new JLabel("Master Password:");
        masterPasswordField = new JPasswordField();
        JLabel passwordLabel = new JLabel("Password:");
        passwordField = new JPasswordField();
        JLabel encryptedPasswordLabel = new JLabel("Encrypted Password:");
        encryptedPasswordField = new JTextField();
        encryptedPasswordField.setEditable(false);
        JLabel decryptedPasswordLabel = new JLabel("Decrypted Password:");
        decryptedPasswordField = new JTextField();
        decryptedPasswordField.setEditable(false);

        JButton encryptButton = new JButton("Encrypt");
        JButton decryptButton = new JButton("Decrypt");

        encryptButton.addActionListener(this);
        decryptButton.addActionListener(this);

        mainPanel.add(masterPasswordLabel);
        mainPanel.add(masterPasswordField);
        mainPanel.add(passwordLabel);
        mainPanel.add(passwordField);
        mainPanel.add(encryptedPasswordLabel);
        mainPanel.add(encryptedPasswordField);
        mainPanel.add(decryptedPasswordLabel);
        mainPanel.add(decryptedPasswordField);
        mainPanel.add(encryptButton);
        mainPanel.add(decryptButton);

        setContentPane(mainPanel);
        setVisible(true);
    }

    private static byte[] generateSalt() {
        byte[] salt = new byte[SALT_LENGTH];
        new SecureRandom().nextBytes(salt);
        return salt;
    }

    private static SecretKey deriveKey(char[] masterPassword, byte[] salt) throws Exception {
        KeySpec spec = new PBEKeySpec(masterPassword, salt, ITERATIONS, KEY_LENGTH);
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        byte[] keyBytes = factory.generateSecret(spec).getEncoded();
        return new SecretKeySpec(keyBytes, SECRET_KEY_ALGORITHM);
    }

    private String encrypt(String masterPassword, String password) {
        try {
            byte[] salt = generateSalt();
            SecretKey key = deriveKey(masterPassword.toCharArray(), salt);
            Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM);
            byte[] iv = new byte[IV_LENGTH];
            new SecureRandom().nextBytes(iv);
            IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);
            cipher.init(Cipher.ENCRYPT_MODE, key, ivParameterSpec);
            byte[] encrypted = cipher.doFinal(password.getBytes());
            byte[] combined = new byte[salt.length + iv.length + encrypted.length];
            System.arraycopy(salt, 0, combined, 0, salt.length);
            System.arraycopy(iv, 0, combined, salt.length, iv.length);
            System.arraycopy(encrypted, 0, combined, salt.length + iv.length, encrypted.length);
            String encryptedPassword = Base64.getEncoder().encodeToString(combined);

            // Write encrypted password to file
            writeToFile(encryptedPassword);

            return encryptedPassword;
        } catch (Exception e) {
            JOptionPane.showMessageDialog(this, "Encryption failed: " + e.getMessage(), "Error", JOptionPane.ERROR_MESSAGE);
            return null;
        }
    }

    private void writeToFile(String encryptedPassword) {
        try (BufferedWriter writer = new BufferedWriter(new FileWriter(ENCRYPTED_PASSWORD_FILE))) {
            writer.write(encryptedPassword);
        } catch (IOException e) {
            JOptionPane.showMessageDialog(this, "Failed to write encrypted password to file", "Error", JOptionPane.ERROR_MESSAGE);
        }
    }

    private String decrypt(String masterPassword, String encryptedPassword) {
        try {
            byte[] combined = Base64.getDecoder().decode(encryptedPassword);
            byte[] salt = new byte[SALT_LENGTH];
            byte[] iv = new byte[IV_LENGTH];
            byte[] encrypted = new byte[combined.length - salt.length - iv.length];
            System.arraycopy(combined, 0, salt, 0, salt.length);
            System.arraycopy(combined, salt.length, iv, 0, iv.length);
            System.arraycopy(combined, salt.length + iv.length, encrypted, 0, encrypted.length);
            SecretKey key = deriveKey(masterPassword.toCharArray(), salt);
            Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM);
            cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(iv));
            byte[] decrypted = cipher.doFinal(encrypted);
            return new String(decrypted);
        } catch (Exception e) {
            JOptionPane.showMessageDialog(this, "Decryption failed: " + e.getMessage(), "Error", JOptionPane.ERROR_MESSAGE);
            return null;
        }
    }

    @Override
    public void actionPerformed(ActionEvent e) {
        if (e.getActionCommand().equals("Encrypt")) {
            String masterPassword = masterPasswordField.getText();
            String password = passwordField.getText();
            String encryptedPassword = encrypt(masterPassword, password);
            if (encryptedPassword != null) {
                encryptedPasswordField.setText(encryptedPassword);
            }
        } else if (e.getActionCommand().equals("Decrypt")) {
            String masterPassword = masterPasswordField.getText();
            String encryptedPassword = encryptedPasswordField.getText();
            String decryptedPassword = decrypt(masterPassword, encryptedPassword);
            if (decryptedPassword != null) {
                decryptedPasswordField.setText(decryptedPassword);
            }
        }
    }

    public static void main(String[] args) {
        SwingUtilities.invokeLater(PasswordManagerGUI::new);
    }
}
