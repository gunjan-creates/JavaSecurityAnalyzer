package com.securityanalyzer.model;

import java.io.Serializable;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

/**
 * Represents the results of a port scanning operation.
 * Contains scan metadata, individual port results, and vulnerability assessments.
 */
public class PortScanResult implements Serializable {

    private static final long serialVersionUID = 1L;

    private final String id;
    private final LocalDateTime timestamp;
    private final String targetHost;
    private final int startPort;
    private final int endPort;
    private final long scanDurationMs;
    private final List<SinglePortResult> portResults;
    private int openPortsCount;
    private int closedPortsCount;
    private int filteredPortsCount;
    private int vulnerablePortsCount;
    private ScanStatus status;

    /**
     * Enumeration for scan status.
     */
    public enum ScanStatus {
        IN_PROGRESS("In Progress"),
        COMPLETED("Completed"),
        CANCELLED("Cancelled"),
        FAILED("Failed");

        private final String displayName;

        ScanStatus(String displayName) {
            this.displayName = displayName;
        }

        public String getDisplayName() {
            return displayName;
        }
    }

    /**
     * Represents the result for a single port scan.
     */
    public static class SinglePortResult implements Serializable {

        private static final long serialVersionUID = 1L;

        private final int port;
        private final PortStatus status;
        private final String service;
        private final String banner;
        private final List<Vulnerability> vulnerabilities;
        private final long responseTimeMs;

        public SinglePortResult(int port, PortStatus status, String service, String banner, List<Vulnerability> vulnerabilities, long responseTimeMs) {
            this.port = port;
            this.status = status;
            this.service = service != null ? service : "Unknown";
            this.banner = banner != null ? banner : "";
            this.vulnerabilities = vulnerabilities != null ? new ArrayList<>(vulnerabilities) : new ArrayList<>();
            this.responseTimeMs = responseTimeMs;
        }

        // Getters
        public int getPort() { return port; }
        public PortStatus getStatus() { return status; }
        public String getService() { return service; }
        public String getBanner() { return banner; }
        public List<Vulnerability> getVulnerabilities() { return new ArrayList<>(vulnerabilities); }
        public long getResponseTimeMs() { return responseTimeMs; }

        public boolean isOpen() { return status == PortStatus.OPEN; }
        public boolean isVulnerable() { return !vulnerabilities.isEmpty(); }
        public int getVulnerabilityCount() { return vulnerabilities.size(); }
    }

    /**
     * Enumeration for port status.
     */
    public enum PortStatus {
        OPEN("Open"),
        CLOSED("Closed"),
        FILTERED("Filtered");

        private final String displayName;

        PortStatus(String displayName) {
            this.displayName = displayName;
        }

        public String getDisplayName() {
            return displayName;
        }
    }

    /**
     * Represents a security vulnerability associated with a port.
     */
    public static class Vulnerability implements Serializable {

        private static final long serialVersionUID = 1L;

        private final String id;
        private final String name;
        private final String description;
        private final Severity severity;
        private final String cveId;
        private final String cvssScore;

        public enum Severity {
            CRITICAL("Critical", "#D32F2F"),
            HIGH("High", "#F57C00"),
            MEDIUM("Medium", "#FBC02D"),
            LOW("Low", "#388E3C"),
            INFO("Info", "#1976D2");

            private final String displayName;
            private final String colorCode;

            Severity(String displayName, String colorCode) {
                this.displayName = displayName;
                this.colorCode = colorCode;
            }

            public String getDisplayName() { return displayName; }
            public String getColorCode() { return colorCode; }
        }

        public Vulnerability(String id, String name, String description, Severity severity, String cveId, String cvssScore) {
            this.id = id != null ? id : UUID.randomUUID().toString();
            this.name = name;
            this.description = description;
            this.severity = severity;
            this.cveId = cveId;
            this.cvssScore = cvssScore;
        }

        // Getters
        public String getId() { return id; }
        public String getName() { return name; }
        public String getDescription() { return description; }
        public Severity getSeverity() { return severity; }
        public String getCveId() { return cveId; }
        public String getCvssScore() { return cvssScore; }
    }

    /**
     * Constructs a new PortScanResult.
     *
     * @param targetHost The target host that was scanned
     * @param startPort The starting port number
     * @param endPort The ending port number
     * @param scanDurationMs The duration of the scan in milliseconds
     */
    public PortScanResult(String targetHost, int startPort, int endPort, long scanDurationMs) {
        this.id = UUID.randomUUID().toString();
        this.timestamp = LocalDateTime.now();
        this.targetHost = targetHost;
        this.startPort = startPort;
        this.endPort = endPort;
        this.scanDurationMs = scanDurationMs;
        this.portResults = new ArrayList<>();
        this.status = ScanStatus.IN_PROGRESS;
        this.openPortsCount = 0;
        this.closedPortsCount = 0;
        this.filteredPortsCount = 0;
        this.vulnerablePortsCount = 0;
    }

    // Getters
    public String getId() { return id; }
    public LocalDateTime getTimestamp() { return timestamp; }
    public String getTargetHost() { return targetHost; }
    public int getStartPort() { return startPort; }
    public int getEndPort() { return endPort; }
    public long getScanDurationMs() { return scanDurationMs; }
    public List<SinglePortResult> getPortResults() { return new ArrayList<>(portResults); }
    public int getOpenPortsCount() { return openPortsCount; }
    public int getClosedPortsCount() { return closedPortsCount; }
    public int getFilteredPortsCount() { return filteredPortsCount; }
    public int getVulnerablePortsCount() { return vulnerablePortsCount; }
    public ScanStatus getStatus() { return status; }

    // Setters
    public void setStatus(ScanStatus status) { this.status = status; }

    /**
     * Adds a port result to the scan results.
     *
     * @param portResult The port result to add
     */
    public void addPortResult(SinglePortResult portResult) {
        if (portResult != null) {
            portResults.add(portResult);
            updateCounts();
        }
    }

    /**
     * Updates the port counts based on current results.
     */
    private void updateCounts() {
        openPortsCount = 0;
        closedPortsCount = 0;
        filteredPortsCount = 0;
        vulnerablePortsCount = 0;

        for (SinglePortResult result : portResults) {
            switch (result.getStatus()) {
                case OPEN:
                    openPortsCount++;
                    break;
                case CLOSED:
                    closedPortsCount++;
                    break;
                case FILTERED:
                    filteredPortsCount++;
                    break;
            }

            if (result.isVulnerable()) {
                vulnerablePortsCount++;
            }
        }
    }

    /**
     * Returns the total number of ports scanned.
     *
     * @return Total ports count
     */
    public int getTotalPortsCount() {
        return endPort - startPort + 1;
    }

    /**
     * Returns the scan progress as a percentage.
     *
     * @return Progress percentage (0-100)
     */
    public double getProgressPercentage() {
        int totalScanned = portResults.size();
        int totalToScan = getTotalPortsCount();
        return totalToScan > 0 ? (double) totalScanned / totalToScan * 100 : 0;
    }

    /**
     * Returns only the open ports from the scan results.
     *
     * @return List of open port results
     */
    public List<SinglePortResult> getOpenPorts() {
        List<SinglePortResult> openPorts = new ArrayList<>();
        for (SinglePortResult result : portResults) {
            if (result.isOpen()) {
                openPorts.add(result);
            }
        }
        return openPorts;
    }

    /**
     * Returns only the vulnerable ports from the scan results.
     *
     * @return List of vulnerable port results
     */
    public List<SinglePortResult> getVulnerablePorts() {
        List<SinglePortResult> vulnerablePorts = new ArrayList<>();
        for (SinglePortResult result : portResults) {
            if (result.isVulnerable()) {
                vulnerablePorts.add(result);
            }
        }
        return vulnerablePorts;
    }

    /**
     * Calculates a security risk score based on scan results.
     *
     * @return Risk score (0-100, higher is more risky)
     */
    public int calculateRiskScore() {
        if (portResults.isEmpty()) {
            return 0;
        }

        int riskScore = 0;

        // Base risk from open ports (more open ports = higher risk)
        int openPortRisk = (int) ((double) openPortsCount / getTotalPortsCount() * 40);
        riskScore += Math.min(40, openPortRisk);

        // Risk from vulnerable ports
        int vulnerabilityRisk = (int) ((double) vulnerablePortsCount / Math.max(1, openPortsCount) * 60);
        riskScore += Math.min(60, vulnerabilityRisk);

        return Math.min(100, riskScore);
    }

    /**
     * Returns a summary of the scan results.
     *
     * @return Formatted summary string
     */
    public String getSummary() {
        return String.format("Port Scan of %s (%d-%d): %d open, %d vulnerable, Duration: %dms",
                targetHost, startPort, endPort, openPortsCount, vulnerablePortsCount, scanDurationMs);
    }

    /**
     * Returns formatted scan duration.
     *
     * @return Human-readable duration string
     */
    public String getFormattedDuration() {
        if (scanDurationMs < 1000) {
            return scanDurationMs + "ms";
        } else if (scanDurationMs < 60000) {
            return String.format("%.2fs", scanDurationMs / 1000.0);
        } else {
            return String.format("%.2fm", scanDurationMs / 60000.0);
        }
    }

    @Override
    public String toString() {
        return "PortScanResult{" +
                "id='" + id + '\'' +
                ", targetHost='" + targetHost + '\'' +
                ", portRange=" + startPort + "-" + endPort +
                ", openPorts=" + openPortsCount +
                ", vulnerablePorts=" + vulnerablePortsCount +
                ", status=" + status +
                ", duration=" + getFormattedDuration() +
                '}';
    }
}