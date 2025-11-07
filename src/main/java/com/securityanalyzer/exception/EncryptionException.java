package com.securityanalyzer.exception;

/**
 * Exception thrown when errors occur during encryption or decryption operations.
 * This includes key generation, file encryption/decryption, and cryptographic operations.
 */
public class EncryptionException extends SecurityAnalysisException {

    /**
     * Constructs a new EncryptionException with null detail message.
     */
    public EncryptionException() {
        super();
    }

    /**
     * Constructs a new EncryptionException with the specified detail message.
     *
     * @param message The detail message explaining the encryption error
     */
    public EncryptionException(String message) {
        super(message);
    }

    /**
     * Constructs a new EncryptionException with the specified detail message and cause.
     *
     * @param message The detail message explaining the encryption error
     * @param cause   The underlying cause of the encryption error
     */
    public EncryptionException(String message, Throwable cause) {
        super(message, cause);
    }

    /**
     * Constructs a new EncryptionException with the specified cause.
     *
     * @param cause The underlying cause of the encryption error
     */
    public EncryptionException(Throwable cause) {
        super(cause);
    }
}