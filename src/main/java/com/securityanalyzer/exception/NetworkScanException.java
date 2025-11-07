package com.securityanalyzer.exception;

/**
 * Exception thrown when errors occur during network scanning operations.
 * This includes port scanning, service detection, and network-related errors.
 */
public class NetworkScanException extends SecurityAnalysisException {

    /**
     * Constructs a new NetworkScanException with null detail message.
     */
    public NetworkScanException() {
        super();
    }

    /**
     * Constructs a new NetworkScanException with the specified detail message.
     *
     * @param message The detail message explaining the network scan error
     */
    public NetworkScanException(String message) {
        super(message);
    }

    /**
     * Constructs a new NetworkScanException with the specified detail message and cause.
     *
     * @param message The detail message explaining the network scan error
     * @param cause   The underlying cause of the network scan error
     */
    public NetworkScanException(String message, Throwable cause) {
        super(message, cause);
    }

    /**
     * Constructs a new NetworkScanException with the specified cause.
     *
     * @param cause The underlying cause of the network scan error
     */
    public NetworkScanException(Throwable cause) {
        super(cause);
    }
}