package com.securityanalyzer.model;

import java.io.Serializable;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

/**
 * Represents the overall security score and risk assessment for the system.
 * Combines analysis from different security categories into a comprehensive score.
 */
public class SecurityScore implements Serializable {

    private static final long serialVersionUID = 1L;

    private final String id;
    private final LocalDateTime timestamp;
    private final Map<Category, Integer> categoryScores;
    private final Map<Category, Integer> categoryWeights;
    private final List<Recommendation> recommendations;
    private int overallScore;
    private RiskLevel riskLevel;
    private String assessmentSummary;

    /**
     * Enumeration for security categories.
     */
    public enum Category {
        PASSWORD_SECURITY("Password Security", 30, "Strength of passwords and authentication practices"),
        NETWORK_SECURITY("Network Security", 40, "Port vulnerabilities and network configuration"),
        ENCRYPTION_PRACTICES("Encryption Practices", 20, "File encryption and key management"),
        SYSTEM_CONFIGURATION("System Configuration", 10, "Overall security hygiene and configuration");

        private final String displayName;
        private final int defaultWeight;
        private final String description;

        Category(String displayName, int defaultWeight, String description) {
            this.displayName = displayName;
            this.defaultWeight = defaultWeight;
            this.description = description;
        }

        public String getDisplayName() {
            return displayName;
        }

        public int getDefaultWeight() {
            return defaultWeight;
        }

        public String getDescription() {
            return description;
        }
    }

    /**
     * Enumeration for risk levels.
     */
    public enum RiskLevel {
        CRITICAL("Critical", 0, 30, "#D32F2F", "Immediate action required - system at high risk"),
        HIGH("High", 31, 50, "#F57C00", "Significant security issues - urgent attention needed"),
        MEDIUM("Medium", 51, 70, "#FBC02D", "Moderate security risks - improvement recommended"),
        LOW("Low", 71, 85, "#388E3C", "Generally secure - minor improvements possible"),
        SECURE("Secure", 86, 100, "#1976D2", "Well secured - maintain current practices");

        private final String displayName;
        private final int minScore;
        private final int maxScore;
        private final String colorCode;
        private final String description;

        RiskLevel(String displayName, int minScore, int maxScore, String colorCode, String description) {
            this.displayName = displayName;
            this.minScore = minScore;
            this.maxScore = maxScore;
            this.colorCode = colorCode;
            this.description = description;
        }

        public String getDisplayName() {
            return displayName;
        }

        public String getColorCode() {
            return colorCode;
        }

        public String getDescription() {
            return description;
        }

        /**
         * Determines risk level based on security score.
         */
        public static RiskLevel fromScore(int score) {
            if (score <= CRITICAL.maxScore) return CRITICAL;
            if (score <= HIGH.maxScore) return HIGH;
            if (score <= MEDIUM.maxScore) return MEDIUM;
            if (score <= LOW.maxScore) return LOW;
            return SECURE;
        }
    }

    /**
     * Represents a security improvement recommendation.
     */
    public static class Recommendation implements Serializable {

        private static final long serialVersionUID = 1L;

        private final String id;
        private final Category category;
        private final Priority priority;
        private final String title;
        private final String description;
        private final String action;
        private final boolean implemented;

        public enum Priority {
            CRITICAL("Critical", "#D32F2F"),
            HIGH("High", "#F57C00"),
            MEDIUM("Medium", "#FBC02D"),
            LOW("Low", "#388E3C");

            private final String displayName;
            private final String colorCode;

            Priority(String displayName, String colorCode) {
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

        public Recommendation(Category category, Priority priority, String title, String description, String action) {
            this.id = UUID.randomUUID().toString();
            this.category = category;
            this.priority = priority;
            this.title = title;
            this.description = description;
            this.action = action;
            this.implemented = false;
        }

        // Getters
        public String getId() { return id; }
        public Category getCategory() { return category; }
        public Priority getPriority() { return priority; }
        public String getTitle() { return title; }
        public String getDescription() { return description; }
        public String getAction() { return action; }
        public boolean isImplemented() { return implemented; }
    }

    /**
     * Constructs a new SecurityScore with default weights.
     */
    public SecurityScore() {
        this.id = UUID.randomUUID().toString();
        this.timestamp = LocalDateTime.now();
        this.categoryScores = new HashMap<>();
        this.categoryWeights = new HashMap<>();
        this.recommendations = new ArrayList<>();
        this.overallScore = 0;
        this.riskLevel = RiskLevel.MEDIUM;

        // Initialize default weights
        for (Category category : Category.values()) {
            categoryWeights.put(category, category.getDefaultWeight());
            categoryScores.put(category, 50); // Default score
        }
    }

    /**
     * Constructs a new SecurityScore with custom weights.
     */
    public SecurityScore(Map<Category, Integer> customWeights) {
        this.id = UUID.randomUUID().toString();
        this.timestamp = LocalDateTime.now();
        this.categoryScores = new HashMap<>();
        this.categoryWeights = new HashMap<>(customWeights);
        this.recommendations = new ArrayList<>();
        this.overallScore = 0;
        this.riskLevel = RiskLevel.MEDIUM;

        // Initialize default scores
        for (Category category : Category.values()) {
            categoryScores.put(category, 50);
        }
    }

    // Getters
    public String getId() { return id; }
    public LocalDateTime getTimestamp() { return timestamp; }
    public Map<Category, Integer> getCategoryScores() { return new HashMap<>(categoryScores); }
    public Map<Category, Integer> getCategoryWeights() { return new HashMap<>(categoryWeights); }
    public List<Recommendation> getRecommendations() { return new ArrayList<>(recommendations); }
    public int getOverallScore() { return overallScore; }
    public RiskLevel getRiskLevel() { return riskLevel; }
    public String getAssessmentSummary() { return assessmentSummary; }

    /**
     * Sets the score for a specific category.
     */
    public void setCategoryScore(Category category, int score) {
        // Clamp score between 0-100
        int clampedScore = Math.max(0, Math.min(100, score));
        categoryScores.put(category, clampedScore);
        calculateOverallScore();
    }

    /**
     * Gets the score for a specific category.
     */
    public int getCategoryScore(Category category) {
        return categoryScores.getOrDefault(category, 0);
    }

    /**
     * Calculates the overall security score based on category scores and weights.
     */
    private void calculateOverallScore() {
        int totalWeightedScore = 0;
        int totalWeight = 0;

        for (Category category : Category.values()) {
            int score = categoryScores.getOrDefault(category, 0);
            int weight = categoryWeights.getOrDefault(category, category.getDefaultWeight());
            totalWeightedScore += score * weight;
            totalWeight += weight;
        }

        overallScore = totalWeight > 0 ? totalWeightedScore / totalWeight : 0;
        riskLevel = RiskLevel.fromScore(overallScore);
        generateAssessmentSummary();
    }

    /**
     * Generates a summary assessment based on the security score.
     */
    private void generateAssessmentSummary() {
        switch (riskLevel) {
            case CRITICAL:
                assessmentSummary = "System has critical security vulnerabilities that require immediate attention.";
                break;
            case HIGH:
                assessmentSummary = "System has significant security issues that should be addressed urgently.";
                break;
            case MEDIUM:
                assessmentSummary = "System has moderate security risks that should be improved.";
                break;
            case LOW:
                assessmentSummary = "System is generally secure with minor security concerns.";
                break;
            case SECURE:
                assessmentSummary = "System demonstrates strong security practices and configuration.";
                break;
        }
    }

    /**
     * Adds a security recommendation.
     */
    public void addRecommendation(Recommendation recommendation) {
        if (recommendation != null) {
            recommendations.add(recommendation);
        }
    }

    /**
     * Adds a security recommendation with specified parameters.
     */
    public void addRecommendation(Category category, Recommendation.Priority priority,
                                String title, String description, String action) {
        addRecommendation(new Recommendation(category, priority, title, description, action));
    }

    /**
     * Gets recommendations for a specific category.
     */
    public List<Recommendation> getRecommendationsByCategory(Category category) {
        List<Recommendation> categoryRecommendations = new ArrayList<>();
        for (Recommendation recommendation : recommendations) {
            if (recommendation.getCategory() == category) {
                categoryRecommendations.add(recommendation);
            }
        }
        return categoryRecommendations;
    }

    /**
     * Gets recommendations by priority level.
     */
    public List<Recommendation> getRecommendationsByPriority(Recommendation.Priority priority) {
        List<Recommendation> priorityRecommendations = new ArrayList<>();
        for (Recommendation recommendation : recommendations) {
            if (recommendation.getPriority() == priority) {
                priorityRecommendations.add(recommendation);
            }
        }
        return priorityRecommendations;
    }

    /**
     * Gets the number of recommendations for each priority level.
     */
    public Map<Recommendation.Priority, Integer> getRecommendationCountByPriority() {
        Map<Recommendation.Priority, Integer> counts = new HashMap<>();
        for (Recommendation.Priority priority : Recommendation.Priority.values()) {
            counts.put(priority, 0);
        }

        for (Recommendation recommendation : recommendations) {
            Recommendation.Priority priority = recommendation.getPriority();
            counts.put(priority, counts.get(priority) + 1);
        }

        return counts;
    }

    /**
     * Calculates the potential score improvement if all recommendations are implemented.
     */
    public int calculatePotentialImprovement() {
        int maxImprovement = 100 - overallScore;
        return Math.min(maxImprovement, recommendations.size() * 5); // Estimate 5 points per recommendation
    }

    /**
     * Returns the score color code based on the risk level.
     */
    public String getScoreColor() {
        return riskLevel.getColorCode();
    }

    /**
     * Returns a formatted score with percentage.
     */
    public String getFormattedScore() {
        return overallScore + "/100";
    }

    /**
     * Returns a comprehensive summary of the security assessment.
     */
    public String getDetailedSummary() {
        StringBuilder summary = new StringBuilder();
        summary.append("Security Assessment Summary:\n");
        summary.append(String.format("Overall Score: %d/100 (%s)\n", overallScore, riskLevel.getDisplayName()));
        summary.append("Category Breakdown:\n");

        for (Category category : Category.values()) {
            int score = categoryScores.getOrDefault(category, 0);
            summary.append(String.format("  - %s: %d/100\n", category.getDisplayName(), score));
        }

        summary.append(String.format("Total Recommendations: %d\n", recommendations.size()));

        if (!recommendations.isEmpty()) {
            summary.append("Priority Breakdown:\n");
            Map<Recommendation.Priority, Integer> priorityCounts = getRecommendationCountByPriority();
            for (Recommendation.Priority priority : Recommendation.Priority.values()) {
                int count = priorityCounts.get(priority);
                if (count > 0) {
                    summary.append(String.format("  - %s: %d\n", priority.getDisplayName(), count));
                }
            }
        }

        return summary.toString();
    }

    @Override
    public String toString() {
        return "SecurityScore{" +
                "id='" + id + '\'' +
                ", overallScore=" + overallScore +
                ", riskLevel=" + riskLevel +
                ", categoryCount=" + categoryScores.size() +
                ", recommendationCount=" + recommendations.size() +
                '}';
    }
}