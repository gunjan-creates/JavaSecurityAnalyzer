package com.securityanalyzer.exception;

/**
 * Exception thrown when errors occur during file operations.
 * This includes file I/O errors, permission issues, and file-related processing errors.
 */
public class FileOperationException extends SecurityAnalysisException {

    /**
     * Constructs a new FileOperationException with null detail message.
     */
    public FileOperationException() {
        super();
    }

    /**
     * Constructs a new FileOperationException with the specified detail message.
     *
     * @param message The detail message explaining the file operation error
     */
    public FileOperationException(String message) {
        super(message);
    }

    /**
     * Constructs a new FileOperationException with the specified detail message and cause.
     *
     * @param message The detail message explaining the file operation error
     * @param cause   The underlying cause of the file operation error
     */
    public FileOperationException(String message, Throwable cause) {
        super(message, cause);
    }

    /**
     * Constructs a new FileOperationException with the specified cause.
     *
     * @param cause The underlying cause of the file operation error
     */
    public FileOperationException(Throwable cause) {
        super(cause);
    }
}