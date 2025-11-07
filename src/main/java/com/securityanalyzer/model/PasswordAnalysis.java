package com.securityanalyzer.model;

import java.io.Serializable;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

/**
 * Represents the results of a password analysis operation.
 * Contains strength score, detected patterns, and improvement suggestions.
 */
public class PasswordAnalysis implements Serializable {

    private static final long serialVersionUID = 1L;

    private final String id;
    private final LocalDateTime timestamp;
    private final String passwordHash; // Hashed representation, not the actual password
    private int strengthScore;
    private int length;
    private boolean hasUppercase;
    private boolean hasLowercase;
    private boolean hasDigits;
    private boolean hasSpecialChars;
    private boolean hasCommonPattern;
    private boolean hasSequentialChars;
    private boolean hasRepeatedChars;
    private boolean hasDictionaryWord;
    private final List<String> detectedPatterns;
    private final List<String> suggestions;
    private String strengthCategory;

    /**
     * Constructs a new PasswordAnalysis with default values.
     */
    public PasswordAnalysis() {
        this.id = UUID.randomUUID().toString();
        this.timestamp = LocalDateTime.now();
        this.passwordHash = "";
        this.strengthScore = 0;
        this.length = 0;
        this.detectedPatterns = new ArrayList<>();
        this.suggestions = new ArrayList<>();
        this.strengthCategory = "Unknown";
    }

    /**
     * Constructs a new PasswordAnalysis with the specified password hash.
     *
     * @param passwordHash Hashed representation of the analyzed password
     */
    public PasswordAnalysis(String passwordHash) {
        this.id = UUID.randomUUID().toString();
        this.timestamp = LocalDateTime.now();
        this.passwordHash = passwordHash;
        this.strengthScore = 0;
        this.length = 0;
        this.detectedPatterns = new ArrayList<>();
        this.suggestions = new ArrayList<>();
        this.strengthCategory = "Unknown";
    }

    // Getters
    public String getId() {
        return id;
    }

    public LocalDateTime getTimestamp() {
        return timestamp;
    }

    public String getPasswordHash() {
        return passwordHash;
    }

    public int getStrengthScore() {
        return strengthScore;
    }

    public int getLength() {
        return length;
    }

    public boolean isHasUppercase() {
        return hasUppercase;
    }

    public boolean isHasLowercase() {
        return hasLowercase;
    }

    public boolean isHasDigits() {
        return hasDigits;
    }

    public boolean isHasSpecialChars() {
        return hasSpecialChars;
    }

    public boolean isHasCommonPattern() {
        return hasCommonPattern;
    }

    public boolean isHasSequentialChars() {
        return hasSequentialChars;
    }

    public boolean isHasRepeatedChars() {
        return hasRepeatedChars;
    }

    public boolean isHasDictionaryWord() {
        return hasDictionaryWord;
    }

    public List<String> getDetectedPatterns() {
        return new ArrayList<>(detectedPatterns);
    }

    public List<String> getSuggestions() {
        return new ArrayList<>(suggestions);
    }

    public String getStrengthCategory() {
        return strengthCategory;
    }

    // Setters
    public void setStrengthScore(int strengthScore) {
        this.strengthScore = Math.max(0, Math.min(100, strengthScore)); // Clamp between 0-100
        updateStrengthCategory();
    }

    public void setLength(int length) {
        this.length = Math.max(0, length);
    }

    public void setHasUppercase(boolean hasUppercase) {
        this.hasUppercase = hasUppercase;
    }

    public void setHasLowercase(boolean hasLowercase) {
        this.hasLowercase = hasLowercase;
    }

    public void setHasDigits(boolean hasDigits) {
        this.hasDigits = hasDigits;
    }

    public void setHasSpecialChars(boolean hasSpecialChars) {
        this.hasSpecialChars = hasSpecialChars;
    }

    public void setHasCommonPattern(boolean hasCommonPattern) {
        this.hasCommonPattern = hasCommonPattern;
    }

    public void setHasSequentialChars(boolean hasSequentialChars) {
        this.hasSequentialChars = hasSequentialChars;
    }

    public void setHasRepeatedChars(boolean hasRepeatedChars) {
        this.hasRepeatedChars = hasRepeatedChars;
    }

    public void setHasDictionaryWord(boolean hasDictionaryWord) {
        this.hasDictionaryWord = hasDictionaryWord;
    }

    public void setStrengthCategory(String strengthCategory) {
        this.strengthCategory = strengthCategory;
    }

    /**
     * Updates the strength category based on the current strength score.
     */
    private void updateStrengthCategory() {
        if (strengthScore >= 80) {
            this.strengthCategory = "Strong";
        } else if (strengthScore >= 60) {
            this.strengthCategory = "Medium";
        } else if (strengthScore >= 40) {
            this.strengthCategory = "Weak";
        } else {
            this.strengthCategory = "Very Weak";
        }
    }

    /**
     * Adds a detected pattern to the analysis results.
     *
     * @param pattern The pattern that was detected
     */
    public void addDetectedPattern(String pattern) {
        if (pattern != null && !pattern.trim().isEmpty()) {
            this.detectedPatterns.add(pattern);
        }
    }

    /**
     * Adds a suggestion for password improvement.
     *
     * @param suggestion The improvement suggestion
     */
    public void addSuggestion(String suggestion) {
        if (suggestion != null && !suggestion.trim().isEmpty()) {
            this.suggestions.add(suggestion);
        }
    }

    /**
     * Returns the color code associated with the strength category.
     *
     * @return CSS color representation for the strength level
     */
    public String getStrengthColor() {
        switch (strengthCategory.toLowerCase()) {
            case "strong":
                return "#4CAF50"; // Green
            case "medium":
                return "#FF9800"; // Orange
            case "weak":
                return "#FF5722"; // Deep Orange
            case "very weak":
                return "#F44336"; // Red
            default:
                return "#9E9E9E"; // Gray
        }
    }

    /**
     * Returns a summary of the password analysis.
     *
     * @return A formatted summary string
     */
    public String getSummary() {
        return String.format("Password Analysis - Strength: %d/100 (%s), Length: %d, Patterns: %d",
                strengthScore, strengthCategory, length, detectedPatterns.size());
    }

    @Override
    public String toString() {
        return "PasswordAnalysis{" +
                "id='" + id + '\'' +
                ", timestamp=" + timestamp +
                ", strengthScore=" + strengthScore +
                ", strengthCategory='" + strengthCategory + '\'' +
                ", length=" + length +
                ", patternsCount=" + detectedPatterns.size() +
                ", suggestionsCount=" + suggestions.size() +
                '}';
    }
}