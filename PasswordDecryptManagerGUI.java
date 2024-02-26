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
import java.nio.charset.StandardCharsets;

public class PasswordDecryptManagerGUI extends JFrame implements ActionListener {

    private static final String SECRET_KEY_ALGORITHM = "AES";
    private static final String CIPHER_ALGORITHM = "AES/CBC/PKCS5Padding";
    private static final int KEY_LENGTH = 256;
    private static final int SALT_LENGTH = 16;
    private static final int ITERATIONS = 65536;
    private static final int IV_LENGTH = 16;
    private static final String ENCRYPTED_PASSWORD_FILE = "encrypted_password.txt";

    private JTextField masterPasswordField, encryptedPasswordField, decryptedPasswordField;

    public PasswordDecryptManagerGUI() {
        setTitle("Password Manager");
        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        setSize(500, 300);
        setLocationRelativeTo(null);

        JPanel mainPanel = new JPanel();
        mainPanel.setLayout(new GridLayout(4, 2, 10, 10));
        mainPanel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));
	
	Font labelFont = new Font("Arial", Font.PLAIN, 16); // Adjust the font size as needed
	Font textFieldFont = new Font("Arial", Font.PLAIN, 16); // Adjust the font size as needed

        JLabel masterPasswordLabel = new JLabel("Master Password:");
	masterPasswordLabel.setFont(labelFont);
        masterPasswordField = new JPasswordField();
	masterPasswordField.setFont(textFieldFont);


        JLabel encryptedPasswordLabel = new JLabel("Encrypted Password:");
	encryptedPasswordLabel.setFont(labelFont);
        encryptedPasswordField = new JTextField();
	encryptedPasswordField.setFont(textFieldFont);


        JLabel decryptedPasswordLabel = new JLabel("Decrypted Password:");
	decryptedPasswordLabel.setFont(labelFont);
        decryptedPasswordField = new JTextField();
        decryptedPasswordField.setEditable(false);
	decryptedPasswordField.setFont(textFieldFont);

        JButton decryptButton = new JButton("Decrypt");

        decryptButton.addActionListener(this);

        mainPanel.add(masterPasswordLabel);
        mainPanel.add(masterPasswordField);
        mainPanel.add(encryptedPasswordLabel);
        mainPanel.add(encryptedPasswordField);
        mainPanel.add(decryptedPasswordLabel);
        mainPanel.add(decryptedPasswordField);
        mainPanel.add(decryptButton);

        setContentPane(mainPanel);
        setVisible(true);
    }

    private static SecretKey deriveKey(char[] masterPassword, byte[] salt) throws Exception {
        KeySpec spec = new PBEKeySpec(masterPassword, salt, ITERATIONS, KEY_LENGTH);
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        byte[] keyBytes = factory.generateSecret(spec).getEncoded();
        return new SecretKeySpec(keyBytes, SECRET_KEY_ALGORITHM);
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
        return new String(decrypted, StandardCharsets.UTF_8); // Ensure proper charset
    } catch (Exception e) {
        JOptionPane.showMessageDialog(this, "Decryption failed: " + e.getMessage(), "Error", JOptionPane.ERROR_MESSAGE);
        return null;
    }
}


    @Override
    public void actionPerformed(ActionEvent e) {
        if (e.getActionCommand().equals("Decrypt")) {
            String masterPassword = masterPasswordField.getText();
            String encryptedPassword = encryptedPasswordField.getText();
            String decryptedPassword = decrypt(masterPassword, encryptedPassword);
            if (decryptedPassword != null) {
                decryptedPasswordField.setText(decryptedPassword);
            }
        }
    }

    public static void main(String[] args) {
        SwingUtilities.invokeLater(PasswordDecryptManagerGUI::new);
    }
}
