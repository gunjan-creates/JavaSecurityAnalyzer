package com.securityanalyzer;

import com.securityanalyzer.model.PasswordAnalysis;
import com.securityanalyzer.service.PasswordAnalysisService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Test class for PasswordAnalysisService.
 * Tests the password strength analysis functionality.
 */
public class PasswordAnalysisServiceTest {

    private PasswordAnalysisService passwordAnalysisService;

    @BeforeEach
    void setUp() {
        passwordAnalysisService = new PasswordAnalysisService();
    }

    @Test
    void testAnalyzeStrongPassword() throws Exception {
        String strongPassword = "MyStr0ng!P@ssw0rd#2024";
        PasswordAnalysis result = passwordAnalysisService.analyzePassword(strongPassword);

        assertNotNull(result);
        assertTrue(result.getStrengthScore() >= 70, "Strong password should score at least 70");
        assertTrue(result.getLength() >= 12, "Password length should be recorded correctly");
        assertTrue(result.isHasUppercase(), "Should detect uppercase letters");
        assertTrue(result.isHasLowercase(), "Should detect lowercase letters");
        assertTrue(result.isHasDigits(), "Should detect digits");
        assertTrue(result.isHasSpecialChars(), "Should detect special characters");
    }

    @Test
    void testAnalyzeWeakPassword() throws Exception {
        String weakPassword = "password";
        PasswordAnalysis result = passwordAnalysisService.analyzePassword(weakPassword);

        assertNotNull(result);
        assertTrue(result.getStrengthScore() < 40, "Weak password should score less than 40");
        assertTrue(result.isHasCommonPattern(), "Should detect common pattern");
        assertTrue(result.isHasDictionaryWord(), "Should detect dictionary word");
        assertFalse(result.isHasDigits(), "Should not detect digits");
        assertFalse(result.isHasSpecialChars(), "Should not detect special characters");
    }

    @Test
    void testAnalyzeEmptyPassword() {
        assertThrows(Exception.class, () -> {
            passwordAnalysisService.analyzePassword(null);
        });

        assertThrows(Exception.class, () -> {
            passwordAnalysisService.analyzePassword("");
        });
    }

    @Test
    void testSequentialCharacterDetection() throws Exception {
        String sequentialPassword = "abc123def";
        PasswordAnalysis result = passwordAnalysisService.analyzePassword(sequentialPassword);

        assertNotNull(result);
        assertTrue(result.isHasSequentialChars(), "Should detect sequential characters");
    }

    @Test
    void testRepeatedCharacterDetection() throws Exception {
        String repeatedPassword = "aaabbbccc";
        PasswordAnalysis result = passwordAnalysisService.analyzePassword(repeatedPassword);

        assertNotNull(result);
        assertTrue(result.isHasRepeatedChars(), "Should detect repeated characters");
    }

    @Test
    void testComplexityScoring() throws Exception {
        String complexPassword = "Cx9!mK2@nQ8#wP5$";
        PasswordAnalysis result = passwordAnalysisService.analyzePassword(complexPassword);

        assertNotNull(result);
        assertTrue(result.getStrengthScore() >= 80, "Complex password should score very high");
        assertTrue(result.getStrengthCategory().equals("Strong"), "Should be categorized as Strong");
    }

    @Test
    void testSuggestionsGeneration() throws Exception {
        String weakPassword = "weak";
        PasswordAnalysis result = passwordAnalysisService.analyzePassword(weakPassword);

        assertNotNull(result);
        assertFalse(result.getSuggestions().isEmpty(), "Should generate suggestions for weak password");
        assertTrue(result.getSuggestions().size() > 3, "Should generate multiple suggestions");
    }

    @Test
    void testMinimumRequirementsValidation() {
        assertTrue(passwordAnalysisService.meetsMinimumRequirements("StrongPassword123!"));
        assertFalse(passwordAnalysisService.meetsMinimumRequirements("weak"));
        assertFalse(passwordAnalysisService.meetsMinimumRequirements(null));
    }
}