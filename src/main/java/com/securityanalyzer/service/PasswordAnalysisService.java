package com.securityanalyzer.service;

import com.nulab.zxcvbn.Strength;
import com.nulab.zxcvbn.Zxcvbn;
import com.securityanalyzer.exception.SecurityAnalysisException;
import com.securityanalyzer.model.PasswordAnalysis;
import org.passay.*;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.regex.Pattern;

/**
 * Service class for analyzing password strength and detecting patterns.
 * Uses Zxcvbn4j for strength scoring and Passay for pattern detection.
 */
public class PasswordAnalysisService {

    private final Zxcvbn zxcvbn;
    private final PasswordValidator passwordValidator;
    private final Pattern sequentialPattern;
    private final Pattern repeatedPattern;
    private final Pattern commonPattern;

    /**
     * Constructs a new PasswordAnalysisService with default validation rules.
     */
    public PasswordAnalysisService() {
        this.zxcvbn = new Zxcvbn();
        this.passwordValidator = createDefaultValidator();

        // Initialize pattern detection regex
        this.sequentialPattern = Pattern.compile("(?:012|123|234|345|456|567|678|789|890|abc|bcd|cde|def|efg|fgh|ghi|hij|ijk|jkl|klm|lmn|mno|nop|opq|pqr|qrs|rst|stu|tuv|uvw|vwx|wxy|xyz)", Pattern.CASE_INSENSITIVE);
        this.repeatedPattern = Pattern.compile("(.)\\1{2,}"); // Three or more repeated characters
        this.commonPattern = Pattern.compile("^(?:(password|admin|user|login|welcome|qwerty|letmein|starwars|iloveyou|monkey|dragon|football|baseball|123456|12345678|123456789|12345))", Pattern.CASE_INSENSITIVE);
    }

    /**
     * Analyzes a password and returns comprehensive analysis results.
     *
     * @param password The password to analyze
     * @return PasswordAnalysis object containing all analysis results
     * @throws SecurityAnalysisException if analysis fails
     */
    public PasswordAnalysis analyzePassword(String password) throws SecurityAnalysisException {
        if (password == null) {
            throw new SecurityAnalysisException("Password cannot be null");
        }

        try {
            PasswordAnalysis analysis = new PasswordAnalysis(hashPassword(password));

            // Basic password properties
            analysis.setLength(password.length());
            analysis.setHasUppercase(!password.equals(password.toLowerCase()));
            analysis.setHasLowercase(!password.equals(password.toUpperCase()));
            analysis.setHasDigits(password.matches(".*\\d.*"));
            analysis.setHasSpecialChars(!password.matches("[a-zA-Z0-9]*"));

            // Perform strength analysis using Zxcvbn
            performStrengthAnalysis(password, analysis);

            // Perform pattern detection using Passay and custom patterns
            performPatternDetection(password, analysis);

            // Generate improvement suggestions
            generateSuggestions(analysis);

            return analysis;

        } catch (Exception e) {
            throw new SecurityAnalysisException("Failed to analyze password", e);
        }
    }

    /**
     * Performs strength analysis using Zxcvbn library.
     *
     * @param password The password to analyze
     * @param analysis The analysis object to update
     */
    private void performStrengthAnalysis(String password, PasswordAnalysis analysis) {
        Strength strength = zxcvbn.measure(password);

        // Convert Zxcvbn score (0-4) to 0-100 scale
        int strengthScore = (int) (strength.getScore() * 25);

        // Apply additional scoring based on password characteristics
        strengthScore += calculateComplexityBonus(password);

        analysis.setStrengthScore(Math.min(100, strengthScore));
    }

    /**
     * Calculates complexity bonus points based on password characteristics.
     *
     * @param password The password to evaluate
     * @return Additional complexity points (0-25)
     */
    private int calculateComplexityBonus(String password) {
        int bonus = 0;

        // Length bonus (up to 10 points)
        if (password.length() >= 12) {
            bonus += 10;
        } else if (password.length() >= 10) {
            bonus += 7;
        } else if (password.length() >= 8) {
            bonus += 4;
        }

        // Character variety bonus (up to 15 points)
        int varietyScore = 0;
        if (!password.equals(password.toLowerCase())) varietyScore += 3; // Uppercase
        if (!password.equals(password.toUpperCase())) varietyScore += 3; // Lowercase
        if (password.matches(".*\\d.*")) varietyScore += 3; // Digits
        if (!password.matches("[a-zA-Z0-9]*")) varietyScore += 3; // Special characters
        if (password.length() > varietyScore * 2) varietyScore += 3; // Length relative to variety

        bonus += Math.min(15, varietyScore);

        return bonus;
    }

    /**
     * Performs pattern detection using Passay library and custom patterns.
     *
     * @param password The password to analyze
     * @param analysis The analysis object to update
     */
    private void performPatternDetection(String password, PasswordAnalysis analysis) {
        // Use Passay to detect basic rule violations
        RuleResult result = passwordValidator.validate(new PasswordData(password));

        if (!result.isValid()) {
            for (String message : passwordValidator.getMessages(result)) {
                analysis.addDetectedPattern(message);
            }
        }

        // Custom pattern detection
        detectCustomPatterns(password, analysis);
    }

    /**
     * Detects custom patterns not covered by Passay rules.
     *
     * @param password The password to analyze
     * @param analysis The analysis object to update
     */
    private void detectCustomPatterns(String password, PasswordAnalysis analysis) {
        // Detect sequential characters
        if (sequentialPattern.matcher(password).find()) {
            analysis.setHasSequentialChars(true);
            analysis.addDetectedPattern("Contains sequential characters");
        }

        // Detect repeated characters
        if (repeatedPattern.matcher(password).find()) {
            analysis.setHasRepeatedChars(true);
            analysis.addDetectedPattern("Contains repeated characters");
        }

        // Detect common patterns
        if (commonPattern.matcher(password).find()) {
            analysis.setHasCommonPattern(true);
            analysis.addDetectedPattern("Contains common pattern or word");
        }

        // Detect keyboard patterns
        if (containsKeyboardPattern(password)) {
            analysis.addDetectedPattern("Contains keyboard pattern");
        }

        // Detect dictionary words
        if (containsDictionaryWord(password.toLowerCase())) {
            analysis.setHasDictionaryWord(true);
            analysis.addDetectedPattern("Contains dictionary word");
        }
    }

    /**
     * Checks if password contains keyboard patterns (qwerty, etc.).
     *
     * @param password The password to check
     * @return True if keyboard pattern detected
     */
    private boolean containsKeyboardPattern(String password) {
        String[] keyboardRows = {
            "qwertyuiop", "asdfghjkl", "zxcvbnm",
            "1234567890"
        };

        String lowerPassword = password.toLowerCase();
        for (String row : keyboardRows) {
            if (row.contains(lowerPassword) || lowerPassword.contains(row)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Checks if password contains common dictionary words.
     * This is a simplified implementation - in production, use a proper dictionary.
     *
     * @param password The password to check
     * @return True if dictionary word detected
     */
    private boolean containsDictionaryWord(String password) {
        String[] commonWords = {
            "password", "admin", "user", "login", "welcome", "security",
            "computer", "internet", "network", "system", "access", "account",
            "private", "public", "secure", "protect", "remember", "secret"
        };

        for (String word : commonWords) {
            if (password.contains(word)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Generates improvement suggestions based on analysis results.
     *
     * @param analysis The analysis object to generate suggestions for
     */
    private void generateSuggestions(PasswordAnalysis analysis) {
        List<String> suggestions = new ArrayList<>();

        if (analysis.getLength() < 12) {
            suggestions.add("Use at least 12 characters");
        }
        if (!analysis.isHasUppercase()) {
            suggestions.add("Include uppercase letters");
        }
        if (!analysis.isHasLowercase()) {
            suggestions.add("Include lowercase letters");
        }
        if (!analysis.isHasDigits()) {
            suggestions.add("Include numbers");
        }
        if (!analysis.isHasSpecialChars()) {
            suggestions.add("Include special characters (!@#$%^&*)");
        }
        if (analysis.isHasSequentialChars()) {
            suggestions.add("Avoid sequential characters (123, abc)");
        }
        if (analysis.isHasRepeatedChars()) {
            suggestions.add("Avoid repeated characters (aaa, 111)");
        }
        if (analysis.isHasCommonPattern()) {
            suggestions.add("Avoid common words and patterns");
        }
        if (analysis.isHasDictionaryWord()) {
            suggestions.add("Avoid dictionary words");
        }

        // Add general suggestions based on strength
        if (analysis.getStrengthScore() < 60) {
            suggestions.add("Consider using a passphrase (e.g., 'correct-horse-battery-staple')");
            suggestions.add("Use a password manager to generate strong unique passwords");
        }

        for (String suggestion : suggestions) {
            analysis.addSuggestion(suggestion);
        }
    }

    /**
     * Creates the default password validator with common rules.
     *
     * @return Configured PasswordValidator
     */
    private PasswordValidator createDefaultValidator() {
        List<Rule> rules = new ArrayList<>();

        // Length rule
        rules.add(new LengthRule(8, 128));

        // Character rules
        rules.add(new CharacterRule(EnglishCharacterData.UpperCase, 1));
        rules.add(new CharacterRule(EnglishCharacterData.LowerCase, 1));
        rules.add(new CharacterRule(EnglishCharacterData.Digit, 1));
        rules.add(new CharacterRule(EnglishCharacterData.Special, 1));

        // Whitespace rule
        rules.add(new WhitespaceRule());

        // Dictionary rule
        rules.add(new DictionaryRule());

        // Illegal character sequence rule
        rules.add(new IllegalSequenceRule(EnglishSequenceData.Alphabetical, 3, false));
        rules.add(new IllegalSequenceRule(EnglishSequenceData.Numerical, 3, false));
        rules.add(new IllegalSequenceRule(EnglishSequenceData.USQwerty, 3, false));

        return new PasswordValidator(rules);
    }

    /**
     * Creates a hash of the password for storage (never store actual passwords).
     *
     * @param password The password to hash
     * @return SHA-256 hash of the password
     */
    private String hashPassword(String password) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hashBytes = digest.digest(password.getBytes());
            return bytesToHex(hashBytes);
        } catch (NoSuchAlgorithmException e) {
            // Fallback to simple hash if SHA-256 not available
            return Integer.toHexString(password.hashCode());
        }
    }

    /**
     * Converts byte array to hexadecimal string.
     *
     * @param bytes The byte array to convert
     * @return Hexadecimal string representation
     */
    private String bytesToHex(byte[] bytes) {
        StringBuilder hexString = new StringBuilder();
        for (byte b : bytes) {
            String hex = Integer.toHexString(0xff & b);
            if (hex.length() == 1) {
                hexString.append('0');
            }
            hexString.append(hex);
        }
        return hexString.toString();
    }

    /**
     * Validates if a password meets minimum security requirements.
     *
     * @param password The password to validate
     * @return True if password meets minimum requirements
     */
    public boolean meetsMinimumRequirements(String password) {
        if (password == null || password.length() < 8) {
            return false;
        }

        PasswordAnalysis analysis;
        try {
            analysis = analyzePassword(password);
            return analysis.getStrengthScore() >= 40; // Minimum acceptable score
        } catch (SecurityAnalysisException e) {
            return false;
        }
    }
}