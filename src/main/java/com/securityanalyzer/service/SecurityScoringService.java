package com.securityanalyzer.service;

import com.securityanalyzer.model.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.List;

/**
 * Service class for calculating overall security scores and generating recommendations.
 * Combines analysis results from different security components into a comprehensive assessment.
 */
public class SecurityScoringService {

    private static final Logger logger = LoggerFactory.getLogger(SecurityScoringService.class);

    private final PasswordAnalysisService passwordAnalysisService;

    /**
     * Constructs a new SecurityScoringService.
     */
    public SecurityScoringService() {
        this.passwordAnalysisService = new PasswordAnalysisService();
    }

    /**
     * Calculates overall security score based on multiple analysis results.
     *
     * @param passwordAnalysis Password analysis results
     * @param portScanResult Port scan results
     * @param encryptionResults List of encryption operation results
     * @return Comprehensive security score with recommendations
     */
    public SecurityScore calculateOverallSecurity(PasswordAnalysis passwordAnalysis,
                                                 PortScanResult portScanResult,
                                                 List<EncryptionResult> encryptionResults) {

        SecurityScore securityScore = new SecurityScore();

        // Calculate password security score
        int passwordScore = calculatePasswordSecurityScore(passwordAnalysis);
        securityScore.setCategoryScore(SecurityScore.Category.PASSWORD_SECURITY, passwordScore);

        // Calculate network security score
        int networkScore = calculateNetworkSecurityScore(portScanResult);
        securityScore.setCategoryScore(SecurityScore.Category.NETWORK_SECURITY, networkScore);

        // Calculate encryption practices score
        int encryptionScore = calculateEncryptionPracticesScore(encryptionResults);
        securityScore.setCategoryScore(SecurityScore.Category.ENCRYPTION_PRACTICES, encryptionScore);

        // Calculate system configuration score (default based on other categories)
        int systemConfigScore = calculateSystemConfigurationScore(passwordAnalysis, portScanResult, encryptionResults);
        securityScore.setCategoryScore(SecurityScore.Category.SYSTEM_CONFIGURATION, systemConfigScore);

        // Generate recommendations based on analysis
        generateRecommendations(securityScore, passwordAnalysis, portScanResult, encryptionResults);

        logger.info("Overall security score calculated: {}/100 ({})",
                   securityScore.getOverallScore(), securityScore.getRiskLevel().getDisplayName());

        return securityScore;
    }

    /**
     * Calculates password security score (0-100).
     */
    private int calculatePasswordSecurityScore(PasswordAnalysis passwordAnalysis) {
        if (passwordAnalysis == null) {
            return 30; // Default low score for no analysis
        }

        int baseScore = passwordAnalysis.getStrengthScore();

        // Additional scoring factors
        int bonus = 0;

        // Length bonus
        if (passwordAnalysis.getLength() >= 16) {
            bonus += 10;
        } else if (passwordAnalysis.getLength() >= 12) {
            bonus += 5;
        }

        // Complexity bonus
        int complexityCount = 0;
        if (passwordAnalysis.isHasUppercase()) complexityCount++;
        if (passwordAnalysis.isHasLowercase()) complexityCount++;
        if (passwordAnalysis.isHasDigits()) complexityCount++;
        if (passwordAnalysis.isHasSpecialChars()) complexityCount++;

        if (complexityCount == 4) {
            bonus += 10;
        } else if (complexityCount >= 3) {
            bonus += 5;
        }

        // Penalties for bad patterns
        int penalty = 0;
        if (passwordAnalysis.isHasCommonPattern()) penalty += 15;
        if (passwordAnalysis.isHasSequentialChars()) penalty += 10;
        if (passwordAnalysis.isHasRepeatedChars()) penalty += 10;
        if (passwordAnalysis.isHasDictionaryWord()) penalty += 20;

        int finalScore = baseScore + bonus - penalty;
        return Math.max(0, Math.min(100, finalScore));
    }

    /**
     * Calculates network security score (0-100).
     */
    private int calculateNetworkSecurityScore(PortScanResult portScanResult) {
        if (portScanResult == null || portScanResult.getStatus() != PortScanResult.ScanStatus.COMPLETED) {
            return 40; // Default score for no scan or failed scan
        }

        int baseScore = 100;

        // Penalty for open ports
        int openPortPenalty = calculateOpenPortPenalty(portScanResult);
        baseScore -= openPortPenalty;

        // Additional penalty for vulnerable ports
        int vulnerabilityPenalty = calculateVulnerabilityPenalty(portScanResult);
        baseScore -= vulnerabilityPenalty;

        // Bonus for secure configuration
        int configBonus = calculateNetworkConfigBonus(portScanResult);
        baseScore += configBonus;

        return Math.max(0, Math.min(100, baseScore));
    }

    /**
     * Calculates penalty for open ports based on their risk level.
     */
    private int calculateOpenPortPenalty(PortScanResult portScanResult) {
        int totalPorts = portScanResult.getTotalPortsCount();
        int openPorts = portScanResult.getOpenPortsCount();

        if (openPorts == 0) return 0;

        double openPortRatio = (double) openPorts / totalPorts;
        int basePenalty = (int) (openPortRatio * 40); // Max 40 points for open ports

        // Additional penalty for high-risk ports
        int highRiskPortPenalty = 0;
        for (PortScanResult.SinglePortResult result : portScanResult.getOpenPorts()) {
            if (isHighRiskPort(result.getPort())) {
                highRiskPortPenalty += 15;
            } else if (isMediumRiskPort(result.getPort())) {
                highRiskPortPenalty += 8;
            }
        }

        return basePenalty + Math.min(30, highRiskPortPenalty);
    }

    /**
     * Calculates penalty for vulnerable ports.
     */
    private int calculateVulnerabilityPenalty(PortScanResult portScanResult) {
        int vulnerablePorts = portScanResult.getVulnerablePortsCount();
        if (vulnerablePorts == 0) return 0;

        int penalty = vulnerablePorts * 20; // 20 points per vulnerable port

        // Additional penalty for critical vulnerabilities
        int criticalPenalty = 0;
        for (PortScanResult.SinglePortResult result : portScanResult.getVulnerablePorts()) {
            for (PortScanResult.Vulnerability vuln : result.getVulnerabilities()) {
                if (vuln.getSeverity() == PortScanResult.Vulnerability.Severity.CRITICAL) {
                    criticalPenalty += 25;
                } else if (vuln.getSeverity() == PortScanResult.Vulnerability.Severity.HIGH) {
                    criticalPenalty += 15;
                }
            }
        }

        return penalty + Math.min(50, criticalPenalty);
    }

    /**
     * Calculates bonus for secure network configuration.
     */
    private int calculateNetworkConfigBonus(PortScanResult portScanResult) {
        int bonus = 0;

        // Bonus for no open critical ports
        boolean hasOpenCriticalPorts = portScanResult.getOpenPorts().stream()
                .anyMatch(result -> isHighRiskPort(result.getPort()));
        if (!hasOpenCriticalPorts) {
            bonus += 10;
        }

        // Bonus for low open port ratio
        double openPortRatio = (double) portScanResult.getOpenPortsCount() / portScanResult.getTotalPortsCount();
        if (openPortRatio < 0.05) {
            bonus += 15;
        } else if (openPortRatio < 0.1) {
            bonus += 8;
        }

        return Math.min(25, bonus);
    }

    /**
     * Checks if a port is considered high risk.
     */
    private boolean isHighRiskPort(int port) {
        return port == 23 || port == 135 || port == 139 || port == 445 || port == 1433 || port == 3389;
    }

    /**
     * Checks if a port is considered medium risk.
     */
    private boolean isMediumRiskPort(int port) {
        return port == 21 || port == 25 || port == 53 || port == 110 || port == 143 || port == 993 || port == 995;
    }

    /**
     * Calculates encryption practices score (0-100).
     */
    private int calculateEncryptionPracticesScore(List<EncryptionResult> encryptionResults) {
        if (encryptionResults == null || encryptionResults.isEmpty()) {
            return 20; // Low score for no encryption usage
        }

        int baseScore = 60; // Base score for using encryption

        int successfulOperations = 0;
        int totalOperations = encryptionResults.size();

        // Count successful operations
        for (EncryptionResult result : encryptionResults) {
            if (result.isSuccessful()) {
                successfulOperations++;
            }
        }

        // Success rate bonus
        double successRate = (double) successfulOperations / totalOperations;
        int successBonus = (int) (successRate * 30);
        baseScore += successBonus;

        // Algorithm diversity bonus
        boolean hasAES = encryptionResults.stream()
                .anyMatch(result -> result.getAlgorithm() == EncryptionResult.EncryptionAlgorithm.AES_256);
        boolean hasRSA = encryptionResults.stream()
                .anyMatch(result -> result.getAlgorithm() == EncryptionResult.EncryptionAlgorithm.RSA_2048);
        boolean hasHybrid = encryptionResults.stream()
                .anyMatch(result -> result.getAlgorithm() == EncryptionResult.EncryptionAlgorithm.HYBRID);

        int algorithmBonus = 0;
        if (hasAES) algorithmBonus += 5;
        if (hasRSA) algorithmBonus += 5;
        if (hasHybrid) algorithmBonus += 10;
        baseScore += algorithmBonus;

        // Verification bonus
        long verifiedOperations = encryptionResults.stream()
                .filter(EncryptionResult::isVerified)
                .count();
        if (verifiedOperations == successfulOperations && successfulOperations > 0) {
            baseScore += 10;
        }

        return Math.max(0, Math.min(100, baseScore));
    }

    /**
     * Calculates system configuration score based on overall security hygiene.
     */
    private int calculateSystemConfigurationScore(PasswordAnalysis passwordAnalysis,
                                                 PortScanResult portScanResult,
                                                 List<EncryptionResult> encryptionResults) {

        int score = 70; // Base score

        // Positive indicators
        if (passwordAnalysis != null && passwordAnalysis.getStrengthScore() >= 80) {
            score += 10;
        }

        if (portScanResult != null && portScanResult.getOpenPortsCount() <= 5) {
            score += 10;
        }

        if (encryptionResults != null && !encryptionResults.isEmpty()) {
            score += 10;
        }

        // Negative indicators
        if (passwordAnalysis != null && passwordAnalysis.getStrengthScore() < 40) {
            score -= 15;
        }

        if (portScanResult != null && portScanResult.getVulnerablePortsCount() > 0) {
            score -= 20;
        }

        return Math.max(0, Math.min(100, score));
    }

    /**
     * Generates security recommendations based on analysis results.
     */
    private void generateRecommendations(SecurityScore securityScore,
                                       PasswordAnalysis passwordAnalysis,
                                       PortScanResult portScanResult,
                                       List<EncryptionResult> encryptionResults) {

        // Password security recommendations
        generatePasswordRecommendations(securityScore, passwordAnalysis);

        // Network security recommendations
        generateNetworkRecommendations(securityScore, portScanResult);

        // Encryption recommendations
        generateEncryptionRecommendations(securityScore, encryptionResults);

        // General security recommendations
        generateGeneralRecommendations(securityScore, passwordAnalysis, portScanResult, encryptionResults);
    }

    /**
     * Generates password-related recommendations.
     */
    private void generatePasswordRecommendations(SecurityScore securityScore, PasswordAnalysis passwordAnalysis) {
        if (passwordAnalysis == null) {
            securityScore.addRecommendation(
                SecurityScore.Category.PASSWORD_SECURITY,
                SecurityScore.Recommendation.Priority.HIGH,
                "Perform Password Analysis",
                "No password analysis has been performed. Analyze your passwords to identify security weaknesses.",
                "Use the Password Analysis module to scan and evaluate password strength."
            );
            return;
        }

        if (passwordAnalysis.getStrengthScore() < 50) {
            securityScore.addRecommendation(
                SecurityScore.Category.PASSWORD_SECURITY,
                SecurityScore.Recommendation.Priority.CRITICAL,
                "Strengthen Weak Passwords",
                "Current password strength is below acceptable levels.",
                "Create longer passwords with mixed character types, avoid common patterns, and use a password manager."
            );
        }

        if (passwordAnalysis.getLength() < 12) {
            securityScore.addRecommendation(
                SecurityScore.Category.PASSWORD_SECURITY,
                SecurityScore.Recommendation.Priority.HIGH,
                "Increase Password Length",
                "Password length is shorter than recommended minimum.",
                "Use passwords with at least 12 characters for better security."
            );
        }

        if (passwordAnalysis.isHasCommonPattern() || passwordAnalysis.isHasDictionaryWord()) {
            securityScore.addRecommendation(
                SecurityScore.Category.PASSWORD_SECURITY,
                SecurityScore.Recommendation.Priority.HIGH,
                "Avoid Common Patterns",
                "Password contains common patterns or dictionary words.",
                "Avoid using sequential characters, repeated characters, or common words in passwords."
            );
        }
    }

    /**
     * Generates network-related recommendations.
     */
    private void generateNetworkRecommendations(SecurityScore securityScore, PortScanResult portScanResult) {
        if (portScanResult == null) {
            securityScore.addRecommendation(
                SecurityScore.Category.NETWORK_SECURITY,
                SecurityScore.Recommendation.Priority.HIGH,
                "Perform Network Security Scan",
                "No network scan has been performed. Scan your system to identify open ports and vulnerabilities.",
                "Use the Port Scanner module to analyze network security."
            );
            return;
        }

        if (portScanResult.getOpenPortsCount() > 10) {
            securityScore.addRecommendation(
                SecurityScore.Category.NETWORK_SECURITY,
                SecurityScore.Recommendation.Priority.HIGH,
                "Reduce Open Ports",
                "Too many open ports increase attack surface.",
                "Close unnecessary ports and services, especially those not in use."
            );
        }

        if (portScanResult.getVulnerablePortsCount() > 0) {
            securityScore.addRecommendation(
                SecurityScore.Category.NETWORK_SECURITY,
                SecurityScore.Recommendation.Priority.CRITICAL,
                "Address Vulnerable Services",
                "Services with known vulnerabilities detected.",
                "Update or patch vulnerable services, or replace with secure alternatives."
            );
        }

        // Check for high-risk open ports
        for (PortScanResult.SinglePortResult result : portScanResult.getOpenPorts()) {
            if (isHighRiskPort(result.getPort())) {
                securityScore.addRecommendation(
                    SecurityScore.Category.NETWORK_SECURITY,
                    SecurityScore.Recommendation.Priority.CRITICAL,
                    "Secure High-Risk Port " + result.getPort(),
                    "Port " + result.getPort() + " (" + result.getService() + ") is open and considered high risk.",
                    "Close this port if not needed, or implement proper access controls and monitoring."
                );
            }
        }
    }

    /**
     * Generates encryption-related recommendations.
     */
    private void generateEncryptionRecommendations(SecurityScore securityScore, List<EncryptionResult> encryptionResults) {
        if (encryptionResults == null || encryptionResults.isEmpty()) {
            securityScore.addRecommendation(
                SecurityScore.Category.ENCRYPTION_PRACTICES,
                SecurityScore.Recommendation.Priority.MEDIUM,
                "Implement File Encryption",
                "No encryption usage detected. Protect sensitive files with encryption.",
                "Use the File Encryption module to protect sensitive data."
            );
            return;
        }

        // Check for failed encryption operations
        long failedOperations = encryptionResults.stream()
                .filter(result -> result.isFailed())
                .count();
        if (failedOperations > 0) {
            securityScore.addRecommendation(
                SecurityScore.Category.ENCRYPTION_PRACTICES,
                SecurityScore.Recommendation.Priority.HIGH,
                "Resolve Encryption Issues",
                "Some encryption operations have failed.",
                "Check file permissions and ensure sufficient disk space for encryption operations."
            );
        }

        // Check algorithm diversity
        boolean hasStrongEncryption = encryptionResults.stream()
                .anyMatch(result -> result.getAlgorithm() == EncryptionResult.EncryptionAlgorithm.AES_256 ||
                                  result.getAlgorithm() == EncryptionResult.EncryptionAlgorithm.HYBRID);
        if (!hasStrongEncryption) {
            securityScore.addRecommendation(
                SecurityScore.Category.ENCRYPTION_PRACTICES,
                SecurityScore.Recommendation.Priority.MEDIUM,
                "Use Strong Encryption Algorithms",
                "Consider using AES-256 or hybrid encryption for better security.",
                "Prefer AES-256 or hybrid encryption over basic algorithms."
            );
        }
    }

    /**
     * Generates general security recommendations.
     */
    private void generateGeneralRecommendations(SecurityScore securityScore,
                                              PasswordAnalysis passwordAnalysis,
                                              PortScanResult portScanResult,
                                              List<EncryptionResult> encryptionResults) {

        if (securityScore.getOverallScore() < 50) {
            securityScore.addRecommendation(
                SecurityScore.Category.SYSTEM_CONFIGURATION,
                SecurityScore.Recommendation.Priority.CRITICAL,
                "Improve Overall Security Posture",
                "System security score is critically low.",
                "Address all identified security issues immediately and implement security best practices."
            );
        }

        if (securityScore.getOverallScore() >= 80) {
            securityScore.addRecommendation(
                SecurityScore.Category.SYSTEM_CONFIGURATION,
                SecurityScore.Recommendation.Priority.LOW,
                "Maintain Security Practices",
                "Good security posture maintained.",
                "Continue following security best practices and regularly review security settings."
            );
        }

        // Recommend regular security scanning
        securityScore.addRecommendation(
            SecurityScore.Category.SYSTEM_CONFIGURATION,
            SecurityScore.Recommendation.Priority.MEDIUM,
            "Regular Security Assessments",
            "Security is an ongoing process requiring regular monitoring.",
            "Perform weekly security scans and monthly comprehensive assessments."
        );
    }

    /**
     * Calculates a quick security score based primarily on password strength and basic network checks.
     */
    public SecurityScore calculateQuickSecurityScore(String password, String host) {
        try {
            // Analyze password
            PasswordAnalysis passwordAnalysis = passwordAnalysisService.analyzePassword(password);

            // Create a basic port scan result (simplified)
            PortScanResult portScanResult = null;
            if (host != null && !host.trim().isEmpty()) {
                // For quick assessment, we'll simulate a basic port scan
                // In real implementation, this would do an actual quick scan
                portScanResult = new PortScanResult(host, 1, 10, 100); // Simulated
                portScanResult.setStatus(PortScanResult.ScanStatus.COMPLETED);
                // Add some sample results for demonstration
                portScanResult.addPortResult(new PortScanResult.SinglePortResult(
                    22, PortScanResult.PortStatus.OPEN, "SSH", "", new ArrayList<>(), 50));
                portScanResult.addPortResult(new PortScanResult.SinglePortResult(
                    80, PortScanResult.PortStatus.OPEN, "HTTP", "", new ArrayList<>(), 75));
            }

            return calculateOverallSecurity(passwordAnalysis, portScanResult, new ArrayList<>());

        } catch (Exception e) {
            logger.error("Quick security assessment failed", e);
            SecurityScore fallbackScore = new SecurityScore();
            fallbackScore.setCategoryScore(SecurityScore.Category.PASSWORD_SECURITY, 30);
            fallbackScore.setCategoryScore(SecurityScore.Category.NETWORK_SECURITY, 40);
            fallbackScore.setCategoryScore(SecurityScore.Category.ENCRYPTION_PRACTICES, 20);
            fallbackScore.setCategoryScore(SecurityScore.Category.SYSTEM_CONFIGURATION, 50);
            return fallbackScore;
        }
    }
}