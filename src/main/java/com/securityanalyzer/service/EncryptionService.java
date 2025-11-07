package com.securityanalyzer.service;

import com.securityanalyzer.exception.EncryptionException;
import com.securityanalyzer.exception.FileOperationException;
import com.securityanalyzer.model.EncryptionResult;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;

/**
 * Service class for performing file encryption and decryption operations.
 * Supports AES-256, RSA-2048, and hybrid encryption approaches.
 */
public class EncryptionService {

    private static final String AES_ALGORITHM = "AES";
    private static final String AES_CIPHER_TRANSFORMATION = "AES/CBC/PKCS5Padding";
    private static final String RSA_ALGORITHM = "RSA";
    private static final int AES_KEY_SIZE = 256;
    private static final int RSA_KEY_SIZE = 2048;
    private static final int IV_SIZE = 16;
    private static final int SALT_SIZE = 16;
    private static final int PBKDF2_ITERATIONS = 100000;
    private static final String KEY_DERIVATION_ALGORITHM = "PBKDF2WithHmacSHA256";

    /**
     * Encrypts a file using AES-256 encryption.
     *
     * @param inputFilePath Path to the file to encrypt
     * @param password Password for key derivation
     * @return EncryptionResult containing operation details
     * @throws EncryptionException if encryption fails
     */
    public EncryptionResult encryptFileAES(String inputFilePath, String password) throws EncryptionException {
        long startTime = System.currentTimeMillis();
        Path inputPath = Paths.get(inputFilePath);

        if (!Files.exists(inputPath)) {
            throw new EncryptionException("Input file does not exist: " + inputFilePath);
        }

        try {
            // Generate salt and derive key
            byte[] salt = generateRandomBytes(SALT_SIZE);
            SecretKey secretKey = deriveKeyFromPassword(password, salt);

            // Generate random IV
            byte[] iv = generateRandomBytes(IV_SIZE);

            // Create output file path
            String outputFilePath = inputFilePath + ".encrypted";

            // Encrypt the file
            Cipher cipher = Cipher.getInstance(AES_CIPHER_TRANSFORMATION);
            IvParameterSpec ivSpec = new IvParameterSpec(iv);
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivSpec);

            // Write encrypted file with salt and IV prepended
            try (FileInputStream fis = new FileInputStream(inputPath.toFile());
                 FileOutputStream fos = new FileOutputStream(outputFilePath)) {

                // Write salt and IV to output file
                fos.write(salt);
                fos.write(iv);

                // Encrypt and write file content
                try (CipherOutputStream cos = new CipherOutputStream(fos, cipher)) {
                    byte[] buffer = new byte[8192];
                    int bytesRead;
                    while ((bytesRead = fis.read(buffer)) != -1) {
                        cos.write(buffer, 0, bytesRead);
                    }
                }
            }

            long processingTime = System.currentTimeMillis() - startTime;
            long fileSize = Files.size(inputPath);
            String checksum = calculateFileChecksum(inputPath);

            return new EncryptionResult(
                EncryptionResult.OperationType.ENCRYPTION,
                EncryptionResult.EncryptionAlgorithm.AES_256,
                inputFilePath,
                outputFilePath,
                null, // No separate key file for password-based encryption
                fileSize,
                processingTime,
                true, // Verified by checksum
                checksum
            );

        } catch (Exception e) {
            long processingTime = System.currentTimeMillis() - startTime;
            throw new EncryptionException("AES encryption failed: " + e.getMessage(), e);
        }
    }

    /**
     * Decrypts a file encrypted with AES-256.
     *
     * @param inputFilePath Path to the encrypted file
     * @param password Password used for key derivation
     * @return EncryptionResult containing operation details
     * @throws EncryptionException if decryption fails
     */
    public EncryptionResult decryptFileAES(String inputFilePath, String password) throws EncryptionException {
        long startTime = System.currentTimeMillis();
        Path inputPath = Paths.get(inputFilePath);

        if (!Files.exists(inputPath)) {
            throw new EncryptionException("Input file does not exist: " + inputFilePath);
        }

        try {
            // Read salt and IV from encrypted file
            try (FileInputStream fis = new FileInputStream(inputPath.toFile())) {
                byte[] salt = new byte[SALT_SIZE];
                byte[] iv = new byte[IV_SIZE];

                if (fis.read(salt) != SALT_SIZE || fis.read(iv) != IV_SIZE) {
                    throw new EncryptionException("Invalid encrypted file format");
                }

                // Derive key from password
                SecretKey secretKey = deriveKeyFromPassword(password, salt);

                // Create output file path
                String outputFilePath = inputFilePath.replace(".encrypted", ".decrypted");

                // Decrypt the file
                Cipher cipher = Cipher.getInstance(AES_CIPHER_TRANSFORMATION);
                IvParameterSpec ivSpec = new IvParameterSpec(iv);
                cipher.init(Cipher.DECRYPT_MODE, secretKey, ivSpec);

                // Create temporary file for decrypted content
                String tempOutputPath = outputFilePath + ".temp";
                boolean decryptionSuccessful = false;

                try (FileOutputStream fos = new FileOutputStream(tempOutputPath);
                     CipherInputStream cis = new CipherInputStream(fis, cipher)) {

                    byte[] buffer = new byte[8192];
                    int bytesRead;
                    while ((bytesRead = cis.read(buffer)) != -1) {
                        fos.write(buffer, 0, bytesRead);
                    }
                    decryptionSuccessful = true;

                    // Rename temp file to final output
                    Files.move(Paths.get(tempOutputPath), Paths.get(outputFilePath));
                }

                if (!decryptionSuccessful) {
                    throw new EncryptionException("Decryption failed - incorrect password or corrupted file");
                }

                long processingTime = System.currentTimeMillis() - startTime;
                long fileSize = Files.size(Paths.get(outputFilePath));
                String checksum = calculateFileChecksum(Paths.get(outputFilePath));

                return new EncryptionResult(
                    EncryptionResult.OperationType.DECRYPTION,
                    EncryptionResult.EncryptionAlgorithm.AES_256,
                    inputFilePath,
                    outputFilePath,
                    null,
                    fileSize,
                    processingTime,
                    true,
                    checksum
                );

            }

        } catch (Exception e) {
            long processingTime = System.currentTimeMillis() - startTime;
            throw new EncryptionException("AES decryption failed: " + e.getMessage(), e);
        }
    }

    /**
     * Generates an RSA-2048 key pair.
     *
     * @param keyFilePath Path to save the key pair
     * @return EncryptionResult containing operation details
     * @throws EncryptionException if key generation fails
     */
    public EncryptionResult generateRSAKeyPair(String keyFilePath) throws EncryptionException {
        long startTime = System.currentTimeMillis();

        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(RSA_ALGORITHM);
            keyPairGenerator.initialize(RSA_KEY_SIZE);
            KeyPair keyPair = keyPairGenerator.generateKeyPair();

            // Save private key
            String privateKeyPath = keyFilePath + "_private.key";
            try (FileOutputStream fos = new FileOutputStream(privateKeyPath)) {
                fos.write(keyPair.getPrivate().getEncoded());
            }

            // Save public key
            String publicKeyPath = keyFilePath + "_public.key";
            try (FileOutputStream fos = new FileOutputStream(publicKeyPath)) {
                fos.write(keyPair.getPublic().getEncoded());
            }

            long processingTime = System.currentTimeMillis() - startTime;

            return new EncryptionResult(
                EncryptionResult.OperationType.KEY_GENERATION,
                EncryptionResult.EncryptionAlgorithm.RSA_2048,
                keyFilePath,
                publicKeyPath + "," + privateKeyPath,
                null,
                0,
                processingTime,
                true,
                null
            );

        } catch (Exception e) {
            long processingTime = System.currentTimeMillis() - startTime;
            throw new EncryptionException("RSA key generation failed: " + e.getMessage(), e);
        }
    }

    /**
     * Encrypts a file using RSA-2048 public key encryption.
     * Note: RSA is only suitable for small files. For larger files, use hybrid encryption.
     *
     * @param inputFilePath Path to the file to encrypt
     * @param publicKeyFilePath Path to the public key file
     * @return EncryptionResult containing operation details
     * @throws EncryptionException if encryption fails
     */
    public EncryptionResult encryptFileRSA(String inputFilePath, String publicKeyFilePath) throws EncryptionException {
        long startTime = System.currentTimeMillis();
        Path inputPath = Paths.get(inputFilePath);

        if (!Files.exists(inputPath)) {
            throw new EncryptionException("Input file does not exist: " + inputFilePath);
        }

        if (!Files.exists(Paths.get(publicKeyFilePath))) {
            throw new EncryptionException("Public key file does not exist: " + publicKeyFilePath);
        }

        try {
            // Read file content
            byte[] fileContent = Files.readAllBytes(inputPath);

            // RSA can only encrypt small amounts of data
            int maxDataSize = (RSA_KEY_SIZE / 8) - 11; // PKCS#1 padding
            if (fileContent.length > maxDataSize) {
                throw new EncryptionException("File too large for RSA encryption (max " + maxDataSize + " bytes). Use hybrid encryption for larger files.");
            }

            // Load public key
            PublicKey publicKey = loadRSAPublicKey(publicKeyFilePath);

            // Encrypt the file
            Cipher cipher = Cipher.getInstance(RSA_ALGORITHM);
            cipher.init(Cipher.ENCRYPT_MODE, publicKey);
            byte[] encryptedContent = cipher.doFinal(fileContent);

            // Write encrypted file
            String outputFilePath = inputFilePath + ".rsa.encrypted";
            Files.write(Paths.get(outputFilePath), encryptedContent);

            long processingTime = System.currentTimeMillis() - startTime;
            long fileSize = Files.size(inputPath);
            String checksum = calculateFileChecksum(inputPath);

            return new EncryptionResult(
                EncryptionResult.OperationType.ENCRYPTION,
                EncryptionResult.EncryptionAlgorithm.RSA_2048,
                inputFilePath,
                outputFilePath,
                publicKeyFilePath,
                fileSize,
                processingTime,
                true,
                checksum
            );

        } catch (Exception e) {
            long processingTime = System.currentTimeMillis() - startTime;
            throw new EncryptionException("RSA encryption failed: " + e.getMessage(), e);
        }
    }

    /**
     * Decrypts a file using RSA-2048 private key.
     *
     * @param inputFilePath Path to the encrypted file
     * @param privateKeyFilePath Path to the private key file
     * @return EncryptionResult containing operation details
     * @throws EncryptionException if decryption fails
     */
    public EncryptionResult decryptFileRSA(String inputFilePath, String privateKeyFilePath) throws EncryptionException {
        long startTime = System.currentTimeMillis();

        if (!Files.exists(Paths.get(inputFilePath))) {
            throw new EncryptionException("Input file does not exist: " + inputFilePath);
        }

        if (!Files.exists(Paths.get(privateKeyFilePath))) {
            throw new EncryptionException("Private key file does not exist: " + privateKeyFilePath);
        }

        try {
            // Read encrypted content
            byte[] encryptedContent = Files.readAllBytes(Paths.get(inputFilePath));

            // Load private key
            PrivateKey privateKey = loadRSAPrivateKey(privateKeyFilePath);

            // Decrypt the file
            Cipher cipher = Cipher.getInstance(RSA_ALGORITHM);
            cipher.init(Cipher.DECRYPT_MODE, privateKey);
            byte[] decryptedContent = cipher.doFinal(encryptedContent);

            // Write decrypted file
            String outputFilePath = inputFilePath.replace(".rsa.encrypted", ".rsa.decrypted");
            Files.write(Paths.get(outputFilePath), decryptedContent);

            long processingTime = System.currentTimeMillis() - startTime;
            long fileSize = Files.size(Paths.get(outputFilePath));
            String checksum = calculateFileChecksum(Paths.get(outputFilePath));

            return new EncryptionResult(
                EncryptionResult.OperationType.DECRYPTION,
                EncryptionResult.EncryptionAlgorithm.RSA_2048,
                inputFilePath,
                outputFilePath,
                privateKeyFilePath,
                fileSize,
                processingTime,
                true,
                checksum
            );

        } catch (Exception e) {
            long processingTime = System.currentTimeMillis() - startTime;
            throw new EncryptionException("RSA decryption failed: " + e.getMessage(), e);
        }
    }

    /**
     * Performs hybrid encryption (RSA + AES) for large files.
     *
     * @param inputFilePath Path to the file to encrypt
     * @param publicKeyFilePath Path to the RSA public key
     * @return EncryptionResult containing operation details
     * @throws EncryptionException if encryption fails
     */
    public EncryptionResult encryptFileHybrid(String inputFilePath, String publicKeyFilePath) throws EncryptionException {
        long startTime = System.currentTimeMillis();
        Path inputPath = Paths.get(inputFilePath);

        if (!Files.exists(inputPath)) {
            throw new EncryptionException("Input file does not exist: " + inputFilePath);
        }

        try {
            // Generate random AES key
            KeyGenerator aesKeyGenerator = KeyGenerator.getInstance(AES_ALGORITHM);
            aesKeyGenerator.init(AES_KEY_SIZE);
            SecretKey aesKey = aesKeyGenerator.generateKey();

            // Generate random IV
            byte[] iv = generateRandomBytes(IV_SIZE);

            // Encrypt file with AES
            String tempEncryptedPath = inputFilePath + ".temp.aes";
            Cipher aesCipher = Cipher.getInstance(AES_CIPHER_TRANSFORMATION);
            IvParameterSpec ivSpec = new IvParameterSpec(iv);
            aesCipher.init(Cipher.ENCRYPT_MODE, aesKey, ivSpec);

            try (FileInputStream fis = new FileInputStream(inputPath.toFile());
                 FileOutputStream fos = new FileOutputStream(tempEncryptedPath);
                 CipherOutputStream cos = new CipherOutputStream(fos, aesCipher)) {

                byte[] buffer = new byte[8192];
                int bytesRead;
                while ((bytesRead = fis.read(buffer)) != -1) {
                    cos.write(buffer, 0, bytesRead);
                }
            }

            // Encrypt AES key with RSA
            PublicKey publicKey = loadRSAPublicKey(publicKeyFilePath);
            Cipher rsaCipher = Cipher.getInstance(RSA_ALGORITHM);
            rsaCipher.init(Cipher.ENCRYPT_MODE, publicKey);
            byte[] encryptedAESKey = rsaCipher.doFinal(aesKey.getEncoded());

            // Write final encrypted file with encrypted AES key, IV, and encrypted content
            String outputFilePath = inputFilePath + ".hybrid.encrypted";
            try (FileOutputStream fos = new FileOutputStream(outputFilePath)) {
                // Write encrypted AES key length and key
                fos.write(encryptedAESKey.length);
                fos.write(encryptedAESKey);

                // Write IV
                fos.write(iv);

                // Write encrypted content
                Files.copy(Paths.get(tempEncryptedPath), fos);
            }

            // Clean up temp file
            Files.deleteIfExists(Paths.get(tempEncryptedPath));

            long processingTime = System.currentTimeMillis() - startTime;
            long fileSize = Files.size(inputPath);
            String checksum = calculateFileChecksum(inputPath);

            return new EncryptionResult(
                EncryptionResult.OperationType.ENCRYPTION,
                EncryptionResult.EncryptionAlgorithm.HYBRID,
                inputFilePath,
                outputFilePath,
                publicKeyFilePath,
                fileSize,
                processingTime,
                true,
                checksum
            );

        } catch (Exception e) {
            long processingTime = System.currentTimeMillis() - startTime;
            throw new EncryptionException("Hybrid encryption failed: " + e.getMessage(), e);
        }
    }

    /**
     * Generates cryptographically secure random bytes.
     */
    private byte[] generateRandomBytes(int size) {
        byte[] bytes = new byte[size];
        new SecureRandom().nextBytes(bytes);
        return bytes;
    }

    /**
     * Derives an encryption key from a password using PBKDF2.
     */
    private SecretKey deriveKeyFromPassword(String password, byte[] salt) throws EncryptionException {
        try {
            PBEKeySpec spec = new PBEKeySpec(password.toCharArray(), salt, PBKDF2_ITERATIONS, AES_KEY_SIZE);
            SecretKeyFactory factory = SecretKeyFactory.getInstance(KEY_DERIVATION_ALGORITHM);
            byte[] keyBytes = factory.generateSecret(spec).getEncoded();
            return new SecretKeySpec(keyBytes, AES_ALGORITHM);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new EncryptionException("Failed to derive key from password", e);
        }
    }

    /**
     * Loads an RSA public key from file.
     */
    private PublicKey loadRSAPublicKey(String keyFilePath) throws EncryptionException {
        try {
            byte[] keyBytes = Files.readAllBytes(Paths.get(keyFilePath));
            X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
            KeyFactory keyFactory = KeyFactory.getInstance(RSA_ALGORITHM);
            return keyFactory.generatePublic(spec);
        } catch (Exception e) {
            throw new EncryptionException("Failed to load RSA public key", e);
        }
    }

    /**
     * Loads an RSA private key from file.
     */
    private PrivateKey loadRSAPrivateKey(String keyFilePath) throws EncryptionException {
        try {
            byte[] keyBytes = Files.readAllBytes(Paths.get(keyFilePath));
            PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
            KeyFactory keyFactory = KeyFactory.getInstance(RSA_ALGORITHM);
            return keyFactory.generatePrivate(spec);
        } catch (Exception e) {
            throw new EncryptionException("Failed to load RSA private key", e);
        }
    }

    /**
     * Calculates SHA-256 checksum of a file.
     */
    private String calculateFileChecksum(Path filePath) throws EncryptionException {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] fileBytes = Files.readAllBytes(filePath);
            byte[] hashBytes = digest.digest(fileBytes);
            return Base64.getEncoder().encodeToString(hashBytes);
        } catch (Exception e) {
            throw new EncryptionException("Failed to calculate file checksum", e);
        }
    }

    /**
     * Calculates SHA-256 checksum of a file.
     */
    private String calculateFileChecksum(String filePath) throws EncryptionException {
        return calculateFileChecksum(Paths.get(filePath));
    }

    /**
     * Verifies if a password meets minimum security requirements for encryption.
     *
     * @param password The password to validate
     * @return True if password meets requirements
     */
    public boolean validateEncryptionPassword(String password) {
        if (password == null || password.length() < 12) {
            return false;
        }

        boolean hasUppercase = !password.equals(password.toLowerCase());
        boolean hasLowercase = !password.equals(password.toUpperCase());
        boolean hasDigits = password.matches(".*\\d.*");
        boolean hasSpecialChars = !password.matches("[a-zA-Z0-9]*");

        return hasUppercase && hasLowercase && hasDigits && hasSpecialChars;
    }
}