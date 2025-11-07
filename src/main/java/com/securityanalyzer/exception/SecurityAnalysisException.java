package com.securityanalyzer.exception;

/**
 * Base exception class for all security analysis related errors.
 * Provides a common base for all security-related exceptions in the application.
 */
public class SecurityAnalysisException extends Exception {

    /**
     * Constructs a new SecurityAnalysisException with null detail message.
     */
    public SecurityAnalysisException() {
        super();
    }

    /**
     * Constructs a new SecurityAnalysisException with the specified detail message.
     *
     * @param message The detail message (which is saved for later retrieval by the getMessage() method)
     */
    public SecurityAnalysisException(String message) {
        super(message);
    }

    /**
     * Constructs a new SecurityAnalysisException with the specified detail message and cause.
     *
     * @param message The detail message (which is saved for later retrieval by the getMessage() method)
     * @param cause   The cause (which is saved for later retrieval by the getCause() method)
     */
    public SecurityAnalysisException(String message, Throwable cause) {
        super(message, cause);
    }

    /**
     * Constructs a new SecurityAnalysisException with the specified cause and a detail message of (cause==null ? null : cause.toString()) (which typically contains the class and detail message of cause).
     *
     * @param cause The cause (which is saved for later retrieval by the getCause() method)
     */
    public SecurityAnalysisException(Throwable cause) {
        super(cause);
    }
}