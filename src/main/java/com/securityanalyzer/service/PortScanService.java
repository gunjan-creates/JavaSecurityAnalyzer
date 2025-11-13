package com.securityanalyzer.service;

import com.securityanalyzer.exception.NetworkScanException;
import com.securityanalyzer.model.PortScanResult;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.net.*;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Service class for performing network port scanning operations.
 * Uses multi-threading for efficient concurrent port scanning.
 */
public class PortScanService {

    private static final Logger logger = LoggerFactory.getLogger(PortScanService.class);

    private static final int DEFAULT_TIMEOUT_MS = 1000;
    private static final int MAX_CONCURRENT_THREADS = 50;
    private static final int DEFAULT_THREAD_POOL_SIZE = 20;

    private final ExecutorService executorService;
    private volatile boolean scanningInProgress = false;
    private volatile boolean scanCancelled = false;

    /**
     * Constructs a new PortScanService with default thread pool.
     */
    public PortScanService() {
        this.executorService = Executors.newFixedThreadPool(DEFAULT_THREAD_POOL_SIZE);
    }

    /**
     * Constructs a new PortScanService with custom thread pool size.
     *
     * @param threadPoolSize Number of threads for concurrent scanning
     */
    public PortScanService(int threadPoolSize) {
        int poolSize = Math.min(Math.max(1, threadPoolSize), MAX_CONCURRENT_THREADS);
        this.executorService = Executors.newFixedThreadPool(poolSize);
    }

    /**
     * Performs a port scan on the specified host and port range.
     *
     * @param targetHost The host to scan
     * @param startPort The starting port number
     * @param endPort The ending port number
     * @return PortScanResult containing all scan results
     * @throws NetworkScanException if scan fails
     */
    public PortScanResult scanPorts(String targetHost, int startPort, int endPort) throws NetworkScanException {
        return scanPorts(targetHost, startPort, endPort, DEFAULT_TIMEOUT_MS);
    }

    /**
     * Performs a port scan with custom timeout.
     *
     * @param targetHost The host to scan
     * @param startPort The starting port number
     * @param endPort The ending port number
     * @param timeoutMs Connection timeout in milliseconds
     * @return PortScanResult containing all scan results
     * @throws NetworkScanException if scan fails
     */
    public PortScanResult scanPorts(String targetHost, int startPort, int endPort, int timeoutMs) throws NetworkScanException {
        validateScanParameters(targetHost, startPort, endPort, timeoutMs);

        if (scanningInProgress) {
            throw new NetworkScanException("Another scan is already in progress");
        }

        scanningInProgress = true;
        scanCancelled = false;

        long startTime = System.currentTimeMillis();
        PortScanResult scanResult = new PortScanResult(targetHost, startPort, endPort, 0);

        try {
            logger.info("Starting port scan on {}: {}-{}", targetHost, startPort, endPort);

            // Resolve target hostname to IP address
            InetAddress targetAddress = resolveTargetHost(targetHost);

            // Perform concurrent port scanning
            performConcurrentScan(targetAddress, startPort, endPort, timeoutMs, scanResult);

            // Calculate final scan duration
            long endTime = System.currentTimeMillis();
            long duration = endTime - startTime;

            PortScanResult finalResult = new PortScanResult(targetHost, startPort, endPort, duration);
            for (PortScanResult.SinglePortResult result : scanResult.getPortResults()) {
                finalResult.addPortResult(result);
            }

            finalResult.setStatus(scanCancelled ? PortScanResult.ScanStatus.CANCELLED : PortScanResult.ScanStatus.COMPLETED);

            logger.info("Port scan completed: {}", finalResult.getSummary());

            return finalResult;

        } catch (Exception e) {
            logger.error("Port scan failed: {}", e.getMessage(), e);
            throw new NetworkScanException("Port scan failed", e);
        } finally {
            scanningInProgress = false;
            scanCancelled = false;
        }
    }

    /**
     * Validates the scan parameters.
     */
    private void validateScanParameters(String targetHost, int startPort, int endPort, int timeoutMs) throws NetworkScanException {
        if (targetHost == null || targetHost.trim().isEmpty()) {
            throw new NetworkScanException("Target host cannot be null or empty");
        }

        if (startPort < 1 || startPort > 65535) {
            throw new NetworkScanException("Start port must be between 1 and 65535");
        }

        if (endPort < 1 || endPort > 65535) {
            throw new NetworkScanException("End port must be between 1 and 65535");
        }

        if (startPort > endPort) {
            throw new NetworkScanException("Start port cannot be greater than end port");
        }

        int portRange = endPort - startPort + 1;
        if (portRange > 10000) {
            throw new NetworkScanException("Port range too large (maximum 10000 ports)");
        }

        if (timeoutMs < 100 || timeoutMs > 10000) {
            throw new NetworkScanException("Timeout must be between 100ms and 10000ms");
        }
    }

    /**
     * Resolves the target host to an IP address.
     */
    private InetAddress resolveTargetHost(String targetHost) throws NetworkScanException {
        try {
            return InetAddress.getByName(targetHost);
        } catch (UnknownHostException e) {
            throw new NetworkScanException("Unable to resolve host: " + targetHost, e);
        }
    }

    /**
     * Performs concurrent port scanning using thread pool.
     */
    private void performConcurrentScan(InetAddress targetAddress, int startPort, int endPort,
                                     int timeoutMs, PortScanResult scanResult) throws NetworkScanException {

        List<Future<PortScanResult.SinglePortResult>> futures = new ArrayList<>();
        AtomicInteger completedScans = new AtomicInteger(0);
        int totalPorts = endPort - startPort + 1;

        // Submit all port scan tasks
        for (int port = startPort; port <= endPort; port++) {
            if (scanCancelled) {
                break;
            }

            final int portToScan = port;
            Future<PortScanResult.SinglePortResult> future = executorService.submit(() -> {
                try {
                    return scanSinglePort(targetAddress, portToScan, timeoutMs);
                } catch (Exception e) {
                    logger.warn("Error scanning port {}: {}", portToScan, e.getMessage());
                    return null;
                } finally {
                    int completed = completedScans.incrementAndGet();
                    if (completed % 100 == 0) {
                        logger.debug("Scanning progress: {}/{} ports", completed, totalPorts);
                    }
                }
            });

            futures.add(future);
        }

        // Collect results
        for (Future<PortScanResult.SinglePortResult> future : futures) {
            if (scanCancelled) {
                future.cancel(true);
                continue;
            }

            try {
                PortScanResult.SinglePortResult result = future.get();
                if (result != null) {
                    scanResult.addPortResult(result);
                }
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                throw new NetworkScanException("Scan interrupted", e);
            } catch (ExecutionException e) {
                logger.warn("Error executing port scan: {}", e.getCause().getMessage());
            }
        }
    }

    /**
     * Scans a single port and returns the result.
     */
    private PortScanResult.SinglePortResult scanSinglePort(InetAddress targetAddress, int port, int timeoutMs) {
        long startTime = System.currentTimeMillis();

        try (Socket socket = new Socket()) {
            // Attempt to connect to the port
            socket.connect(new InetSocketAddress(targetAddress, port), timeoutMs);
            long responseTime = System.currentTimeMillis() - startTime;

            if (socket.isConnected()) {
                // Port is open - detect service and check for vulnerabilities
                String service = detectService(port);
                String banner = grabBanner(socket);
                List<PortScanResult.Vulnerability> vulnerabilities = checkVulnerabilities(port, service, banner);

                return new PortScanResult.SinglePortResult(
                    port,
                    PortScanResult.PortStatus.OPEN,
                    service,
                    banner,
                    vulnerabilities,
                    responseTime
                );
            }

        } catch (SocketTimeoutException e) {
            // Port is filtered (timed out)
            long responseTime = System.currentTimeMillis() - startTime;
            return new PortScanResult.SinglePortResult(
                port,
                PortScanResult.PortStatus.FILTERED,
                "Unknown",
                "",
                new ArrayList<>(),
                responseTime
            );
        } catch (ConnectException | PortUnreachableException e) {
            // Port is closed
            long responseTime = System.currentTimeMillis() - startTime;
            return new PortScanResult.SinglePortResult(
                port,
                PortScanResult.PortStatus.CLOSED,
                "Unknown",
                "",
                new ArrayList<>(),
                responseTime
            );
        } catch (IOException e) {
            // Other network error - treat as filtered
            long responseTime = System.currentTimeMillis() - startTime;
            return new PortScanResult.SinglePortResult(
                port,
                PortScanResult.PortStatus.FILTERED,
                "Unknown",
                "",
                new ArrayList<>(),
                responseTime
            );
        }

        // Should not reach here
        return null;
    }

    /**
     * Attempts to detect the service running on the specified port.
     */
    private String detectService(int port) {
        // Common port services mapping
        switch (port) {
            case 20: return "FTP Data";
            case 21: return "FTP Control";
            case 22: return "SSH";
            case 23: return "Telnet";
            case 25: return "SMTP";
            case 53: return "DNS";
            case 80: return "HTTP";
            case 110: return "POP3";
            case 143: return "IMAP";
            case 443: return "HTTPS";
            case 993: return "IMAPS";
            case 995: return "POP3S";
            case 3389: return "RDP";
            case 5432: return "PostgreSQL";
            case 3306: return "MySQL";
            case 1433: return "MSSQL";
            case 6379: return "Redis";
            case 27017: return "MongoDB";
            default: return "Unknown";
        }
    }

    /**
     * Attempts to grab service banner from the socket.
     */
    private String grabBanner(Socket socket) {
        try {
            if (socket.getInputStream().available() > 0) {
                byte[] buffer = new byte[1024];
                int bytesRead = socket.getInputStream().read(buffer);
                if (bytesRead > 0) {
                    return new String(buffer, 0, bytesRead).trim();
                }
            }
        } catch (IOException e) {
            // Banner grab failed - continue without banner
        }
        return "";
    }

    /**
     * Checks for known vulnerabilities based on port, service, and banner.
     */
    private List<PortScanResult.Vulnerability> checkVulnerabilities(int port, String service, String banner) {
        List<PortScanResult.Vulnerability> vulnerabilities = new ArrayList<>();

        // Check for common vulnerable services
        if (port == 23 && "Telnet".equals(service)) {
            vulnerabilities.add(new PortScanResult.Vulnerability(
                "TELNET-PLAINTEXT",
                "Telnet Service",
                "Telnet transmits data in plaintext, including credentials",
                PortScanResult.Vulnerability.Severity.HIGH,
                null,
                "7.5"
            ));
        }

        if (port == 21 && "FTP Control".equals(service)) {
            vulnerabilities.add(new PortScanResult.Vulnerability(
                "FTP-PLAINTEXT",
                "FTP Service",
                "FTP transmits data in plaintext, including credentials",
                PortScanResult.Vulnerability.Severity.MEDIUM,
                null,
                "5.0"
            ));
        }

        // Check for default credentials in banner
        if (banner != null && !banner.isEmpty()) {
            if (banner.toLowerCase().contains("default") || banner.toLowerCase().contains("password")) {
                vulnerabilities.add(new PortScanResult.Vulnerability(
                    "DEFAULT-CREDS",
                    "Default Credentials Detected",
                    "Service banner suggests default credentials may be in use",
                    PortScanResult.Vulnerability.Severity.HIGH,
                    null,
                    "8.0"
                ));
            }
        }

        // Check for outdated service versions (simplified)
        if (banner != null && !banner.isEmpty()) {
            String lowerBanner = banner.toLowerCase();
            if (lowerBanner.contains("apache/2.2") || lowerBanner.contains("nginx/1.0") ||
                lowerBanner.contains("openssh_5.") || lowerBanner.contains("mysql 5.0")) {
                vulnerabilities.add(new PortScanResult.Vulnerability(
                    "OUTDATED-SERVICE",
                    "Outdated Service Version",
                    "Service appears to be running an outdated version with known vulnerabilities",
                    PortScanResult.Vulnerability.Severity.MEDIUM,
                    null,
                    "6.5"
                ));
            }
        }

        return vulnerabilities;
    }

    /**
     * Cancels the current scan operation.
     */
    public void cancelScan() {
        scanCancelled = true;
        logger.info("Port scan cancellation requested");
    }

    /**
     * Checks if a scan is currently in progress.
     *
     * @return True if a scan is in progress
     */
    public boolean isScanningInProgress() {
        return scanningInProgress;
    }

    /**
     * Shuts down the port scan service and releases resources.
     */
    public void shutdown() {
        try {
            scanCancelled = true;
            executorService.shutdown();

            if (!executorService.awaitTermination(5, TimeUnit.SECONDS)) {
                executorService.shutdownNow();
                if (!executorService.awaitTermination(5, TimeUnit.SECONDS)) {
                    logger.warn("Executor service did not terminate gracefully");
                }
            }
        } catch (InterruptedException e) {
            executorService.shutdownNow();
            Thread.currentThread().interrupt();
        }
    }
}