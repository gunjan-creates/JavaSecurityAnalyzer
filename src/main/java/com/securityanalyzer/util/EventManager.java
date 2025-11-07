package com.securityanalyzer.util;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;

/**
 * Event manager for implementing publish-subscribe pattern in the application.
 * Allows components to communicate without direct dependencies.
 */
public class EventManager {

    private static final EventManager INSTANCE = new EventManager();
    private final Map<Class<? extends Event>, List<EventListener<?>>> listeners;

    private EventManager() {
        this.listeners = new HashMap<>();
    }

    /**
     * Gets the singleton instance of EventManager.
     */
    public static EventManager getInstance() {
        return INSTANCE;
    }

    /**
     * Registers an event listener for a specific event type.
     *
     * @param eventType The class of the event type to listen for
     * @param listener The listener to register
     * @param <T> The event type
     */
    @SuppressWarnings("unchecked")
    public <T extends Event> void addEventListener(Class<T> eventType, EventListener<T> listener) {
        if (eventType == null || listener == null) {
            throw new IllegalArgumentException("Event type and listener cannot be null");
        }

        listeners.computeIfAbsent(eventType, k -> new CopyOnWriteArrayList<>())
                 .add((EventListener<?>) listener);
    }

    /**
     * Removes an event listener for a specific event type.
     *
     * @param eventType The class of the event type
     * @param listener The listener to remove
     * @param <T> The event type
     */
    public <T extends Event> void removeEventListener(Class<T> eventType, EventListener<T> listener) {
        if (eventType == null || listener == null) {
            return;
        }

        List<EventListener<?>> eventListeners = listeners.get(eventType);
        if (eventListeners != null) {
            eventListeners.remove(listener);
            if (eventListeners.isEmpty()) {
                listeners.remove(eventType);
            }
        }
    }

    /**
     * Publishes an event to all registered listeners.
     *
     * @param event The event to publish
     * @param <T> The event type
     */
    @SuppressWarnings("unchecked")
    public <T extends Event> void publishEvent(T event) {
        if (event == null) {
            return;
        }

        List<EventListener<?>> eventListeners = listeners.get(event.getClass());
        if (eventListeners != null) {
            for (EventListener<?> listener : eventListeners) {
                try {
                    ((EventListener<T>) listener).onEvent(event);
                } catch (Exception e) {
                    System.err.println("Error in event listener: " + e.getMessage());
                    e.printStackTrace();
                }
            }
        }
    }

    /**
     * Clears all event listeners.
     */
    public void clearAllListeners() {
        listeners.clear();
    }

    /**
     * Gets the number of listeners for a specific event type.
     *
     * @param eventType The event type to check
     * @return Number of registered listeners
     */
    public int getListenerCount(Class<? extends Event> eventType) {
        List<EventListener<?>> eventListeners = listeners.get(eventType);
        return eventListeners != null ? eventListeners.size() : 0;
    }

    /**
     * Base interface for all events.
     */
    public interface Event {
        long getTimestamp();
        String getEventType();
    }

    /**
     * Interface for event listeners.
     *
     * @param <T> The event type this listener handles
     */
    public interface EventListener<T extends Event> {
        void onEvent(T event);
    }

    /**
     * Base implementation of Event.
     */
    public static abstract class BaseEvent implements Event {
        private final long timestamp;
        private final String eventType;

        protected BaseEvent(String eventType) {
            this.timestamp = System.currentTimeMillis();
            this.eventType = eventType;
        }

        @Override
        public long getTimestamp() {
            return timestamp;
        }

        @Override
        public String getEventType() {
            return eventType;
        }
    }

    /**
     * Event for password analysis completion.
     */
    public static class PasswordAnalysisCompletedEvent extends BaseEvent {
        private final String analysisId;
        private final int strengthScore;
        private final boolean successful;

        public PasswordAnalysisCompletedEvent(String analysisId, int strengthScore, boolean successful) {
            super("PASSWORD_ANALYSIS_COMPLETED");
            this.analysisId = analysisId;
            this.strengthScore = strengthScore;
            this.successful = successful;
        }

        public String getAnalysisId() { return analysisId; }
        public int getStrengthScore() { return strengthScore; }
        public boolean isSuccessful() { return successful; }
    }

    /**
     * Event for port scan progress updates.
     */
    public static class PortScanProgressEvent extends BaseEvent {
        private final String scanId;
        private final int currentPort;
        private final int totalPorts;
        private final int openPortsFound;

        public PortScanProgressEvent(String scanId, int currentPort, int totalPorts, int openPortsFound) {
            super("PORT_SCAN_PROGRESS");
            this.scanId = scanId;
            this.currentPort = currentPort;
            this.totalPorts = totalPorts;
            this.openPortsFound = openPortsFound;
        }

        public String getScanId() { return scanId; }
        public int getCurrentPort() { return currentPort; }
        public int getTotalPorts() { return totalPorts; }
        public int getOpenPortsFound() { return openPortsFound; }
        public double getProgressPercentage() {
            return totalPorts > 0 ? (double) currentPort / totalPorts * 100 : 0;
        }
    }

    /**
     * Event for port scan completion.
     */
    public static class PortScanCompletedEvent extends BaseEvent {
        private final String scanId;
        private final int openPortsCount;
        private final int vulnerablePortsCount;
        private final boolean successful;

        public PortScanCompletedEvent(String scanId, int openPortsCount, int vulnerablePortsCount, boolean successful) {
            super("PORT_SCAN_COMPLETED");
            this.scanId = scanId;
            this.openPortsCount = openPortsCount;
            this.vulnerablePortsCount = vulnerablePortsCount;
            this.successful = successful;
        }

        public String getScanId() { return scanId; }
        public int getOpenPortsCount() { return openPortsCount; }
        public int getVulnerablePortsCount() { return vulnerablePortsCount; }
        public boolean isSuccessful() { return successful; }
    }

    /**
     * Event for encryption operation progress.
     */
    public static class EncryptionProgressEvent extends BaseEvent {
        private final String operationId;
        private final long bytesProcessed;
        private final long totalBytes;
        private final String currentFile;

        public EncryptionProgressEvent(String operationId, long bytesProcessed, long totalBytes, String currentFile) {
            super("ENCRYPTION_PROGRESS");
            this.operationId = operationId;
            this.bytesProcessed = bytesProcessed;
            this.totalBytes = totalBytes;
            this.currentFile = currentFile;
        }

        public String getOperationId() { return operationId; }
        public long getBytesProcessed() { return bytesProcessed; }
        public long getTotalBytes() { return totalBytes; }
        public String getCurrentFile() { return currentFile; }
        public double getProgressPercentage() {
            return totalBytes > 0 ? (double) bytesProcessed / totalBytes * 100 : 0;
        }
    }

    /**
     * Event for encryption operation completion.
     */
    public static class EncryptionCompletedEvent extends BaseEvent {
        private final String operationId;
        private final String operationType;
        private final String algorithm;
        private final boolean successful;
        private final String errorMessage;

        public EncryptionCompletedEvent(String operationId, String operationType, String algorithm, boolean successful, String errorMessage) {
            super("ENCRYPTION_COMPLETED");
            this.operationId = operationId;
            this.operationType = operationType;
            this.algorithm = algorithm;
            this.successful = successful;
            this.errorMessage = errorMessage;
        }

        public String getOperationId() { return operationId; }
        public String getOperationType() { return operationType; }
        public String getAlgorithm() { return algorithm; }
        public boolean isSuccessful() { return successful; }
        public String getErrorMessage() { return errorMessage; }
    }

    /**
     * Event for security score calculation completion.
     */
    public static class SecurityScoreUpdatedEvent extends BaseEvent {
        private final int overallScore;
        private final String riskLevel;
        private final String assessmentSummary;

        public SecurityScoreUpdatedEvent(int overallScore, String riskLevel, String assessmentSummary) {
            super("SECURITY_SCORE_UPDATED");
            this.overallScore = overallScore;
            this.riskLevel = riskLevel;
            this.assessmentSummary = assessmentSummary;
        }

        public int getOverallScore() { return overallScore; }
        public String getRiskLevel() { return riskLevel; }
        public String getAssessmentSummary() { return assessmentSummary; }
    }

    /**
     * Event for application status updates.
     */
    public static class ApplicationStatusEvent extends BaseEvent {
        private final String status;
        private final String message;

        public ApplicationStatusEvent(String status, String message) {
            super("APPLICATION_STATUS");
            this.status = status;
            this.message = message;
        }

        public String getStatus() { return status; }
        public String getMessage() { return message; }
    }
}