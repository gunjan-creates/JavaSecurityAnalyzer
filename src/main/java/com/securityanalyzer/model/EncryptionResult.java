package com.securityanalyzer.model;

import java.io.Serializable;
import java.time.LocalDateTime;
import java.util.UUID;

/**
 * Represents the result of an encryption or decryption operation.
 * Contains operation metadata, status, and verification information.
 */
public class EncryptionResult implements Serializable {

    private static final long serialVersionUID = 1L;

    private final String id;
    private final LocalDateTime timestamp;
    private final OperationType operationType;
    private final EncryptionAlgorithm algorithm;
    private final String originalFilePath;
    private final String processedFilePath;
    private final String keyFilePath;
    private final long fileSize;
    private final long processingTimeMs;
    private final OperationStatus status;
    private final String errorMessage;
    private final boolean verified;
    private final String checksum;

    /**
     * Enumeration for encryption operation types.
     */
    public enum OperationType {
        ENCRYPTION("Encryption"),
        DECRYPTION("Decryption"),
        KEY_GENERATION("Key Generation");

        private final String displayName;

        OperationType(String displayName) {
            this.displayName = displayName;
        }

        public String getDisplayName() {
            return displayName;
        }
    }

    /**
     * Enumeration for encryption algorithms.
     */
    public enum EncryptionAlgorithm {
        AES_256("AES-256", "Advanced Encryption Standard with 256-bit key"),
        RSA_2048("RSA-2048", "RSA with 2048-bit key"),
        HYBRID("Hybrid", "RSA key exchange with AES encryption");

        private final String displayName;
        private final String description;

        EncryptionAlgorithm(String displayName, String description) {
            this.displayName = displayName;
            this.description = description;
        }

        public String getDisplayName() {
            return displayName;
        }

        public String getDescription() {
            return description;
        }
    }

    /**
     * Enumeration for operation status.
     */
    public enum OperationStatus {
        SUCCESS("Success", "#4CAF50"),
        FAILED("Failed", "#F44336"),
        CANCELLED("Cancelled", "#FF9800"),
        IN_PROGRESS("In Progress", "#2196F3");

        private final String displayName;
        private final String colorCode;

        OperationStatus(String displayName, String colorCode) {
            this.displayName = displayName;
            this.colorCode = colorCode;
        }

        public String getDisplayName() {
            return displayName;
        }

        public String getColorCode() {
            return colorCode;
        }
    }

    /**
     * Constructs a new EncryptionResult for a successful operation.
     */
    public EncryptionResult(OperationType operationType, EncryptionAlgorithm algorithm,
                           String originalFilePath, String processedFilePath, String keyFilePath,
                           long fileSize, long processingTimeMs, boolean verified, String checksum) {
        this.id = UUID.randomUUID().toString();
        this.timestamp = LocalDateTime.now();
        this.operationType = operationType;
        this.algorithm = algorithm;
        this.originalFilePath = originalFilePath;
        this.processedFilePath = processedFilePath;
        this.keyFilePath = keyFilePath;
        this.fileSize = fileSize;
        this.processingTimeMs = processingTimeMs;
        this.status = OperationStatus.SUCCESS;
        this.errorMessage = null;
        this.verified = verified;
        this.checksum = checksum;
    }

    /**
     * Constructs a new EncryptionResult for a failed operation.
     */
    public EncryptionResult(OperationType operationType, EncryptionAlgorithm algorithm,
                           String originalFilePath, long processingTimeMs, String errorMessage) {
        this.id = UUID.randomUUID().toString();
        this.timestamp = LocalDateTime.now();
        this.operationType = operationType;
        this.algorithm = algorithm;
        this.originalFilePath = originalFilePath;
        this.processedFilePath = null;
        this.keyFilePath = null;
        this.fileSize = 0;
        this.processingTimeMs = processingTimeMs;
        this.status = OperationStatus.FAILED;
        this.errorMessage = errorMessage;
        this.verified = false;
        this.checksum = null;
    }

    // Getters
    public String getId() { return id; }
    public LocalDateTime getTimestamp() { return timestamp; }
    public OperationType getOperationType() { return operationType; }
    public EncryptionAlgorithm getAlgorithm() { return algorithm; }
    public String getOriginalFilePath() { return originalFilePath; }
    public String getProcessedFilePath() { return processedFilePath; }
    public String getKeyFilePath() { return keyFilePath; }
    public long getFileSize() { return fileSize; }
    public long getProcessingTimeMs() { return processingTimeMs; }
    public OperationStatus getStatus() { return status; }
    public String getErrorMessage() { return errorMessage; }
    public boolean isVerified() { return verified; }
    public String getChecksum() { return checksum; }

    /**
     * Returns the file name from the file path.
     */
    public String getOriginalFileName() {
        if (originalFilePath == null) return "";
        return originalFilePath.substring(Math.max(originalFilePath.lastIndexOf('/'), originalFilePath.lastIndexOf('\\')) + 1);
    }

    /**
     * Returns the processed file name from the file path.
     */
    public String getProcessedFileName() {
        if (processedFilePath == null) return "";
        return processedFilePath.substring(Math.max(processedFilePath.lastIndexOf('/'), processedFilePath.lastIndexOf('\\')) + 1);
    }

    /**
     * Returns the file size in human-readable format.
     */
    public String getFormattedFileSize() {
        if (fileSize < 1024) {
            return fileSize + " B";
        } else if (fileSize < 1024 * 1024) {
            return String.format("%.1f KB", fileSize / 1024.0);
        } else if (fileSize < 1024 * 1024 * 1024) {
            return String.format("%.1f MB", fileSize / (1024.0 * 1024.0));
        } else {
            return String.format("%.1f GB", fileSize / (1024.0 * 1024.0 * 1024.0));
        }
    }

    /**
     * Returns the processing time in human-readable format.
     */
    public String getFormattedProcessingTime() {
        if (processingTimeMs < 1000) {
            return processingTimeMs + "ms";
        } else if (processingTimeMs < 60000) {
            return String.format("%.2fs", processingTimeMs / 1000.0);
        } else {
            return String.format("%.2fm", processingTimeMs / 60000.0);
        }
    }

    /**
     * Returns a summary of the encryption operation.
     */
    public String getSummary() {
        if (status == OperationStatus.SUCCESS) {
            return String.format("%s (%s) of %s completed in %s - %s",
                    operationType.getDisplayName(),
                    algorithm.getDisplayName(),
                    getOriginalFileName(),
                    getFormattedProcessingTime(),
                    verified ? "Verified" : "Not Verified");
        } else {
            return String.format("%s (%s) of %s failed: %s",
                    operationType.getDisplayName(),
                    algorithm.getDisplayName(),
                    getOriginalFileName(),
                    errorMessage);
        }
    }

    /**
     * Returns true if the operation was successful.
     */
    public boolean isSuccessful() {
        return status == OperationStatus.SUCCESS;
    }

    /**
     * Returns true if the operation failed.
     */
    public boolean isFailed() {
        return status == OperationStatus.FAILED;
    }

    /**
     * Returns the verification status as a user-friendly string.
     */
    public String getVerificationStatus() {
        if (status != OperationStatus.SUCCESS) {
            return "N/A";
        }
        return verified ? "✓ Verified" : "⚠ Not Verified";
    }

    /**
     * Returns the verification status color code.
     */
    public String getVerificationStatusColor() {
        if (status != OperationStatus.SUCCESS) {
            return "#9E9E9E"; // Gray
        }
        return verified ? "#4CAF50" : "#FF9800"; // Green or Orange
    }

    @Override
    public String toString() {
        return "EncryptionResult{" +
                "id='" + id + '\'' +
                ", operationType=" + operationType +
                ", algorithm=" + algorithm +
                ", originalFilePath='" + originalFilePath + '\'' +
                ", fileSize=" + getFormattedFileSize() +
                ", processingTime=" + getFormattedProcessingTime() +
                ", status=" + status +
                ", verified=" + verified +
                '}';
    }
}