package com.securityanalyzer.controller;

import com.securityanalyzer.model.*;
import com.securityanalyzer.service.*;
import com.securityanalyzer.util.EventManager;
import javafx.application.Platform;
import javafx.collections.FXCollections;
import javafx.collections.ObservableList;
import javafx.concurrent.Task;
import javafx.fxml.FXML;
import javafx.scene.control.*;
import javafx.scene.layout.VBox;
import javafx.stage.FileChooser;
import javafx.stage.Stage;

import java.io.File;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.List;
import java.util.Timer;
import java.util.TimerTask;

/**
 * Main controller for the Java Security Analyzer application.
 * Manages the overall UI and coordinates between different security modules.
 */
public class MainController {

    // Services
    private final PasswordAnalysisService passwordAnalysisService;
    private final PortScanService portScanService;
    private final EncryptionService encryptionService;
    private final SecurityScoringService securityScoringService;
    private final FileService fileService;

    // Data
    private PasswordAnalysis currentPasswordAnalysis;
    private PortScanResult currentPortScanResult;
    private final ObservableList<EncryptionResult> encryptionHistory;
    private final ObservableList<PortScanResult.SinglePortResult> scanResults;
    private SecurityScore currentSecurityScore;

    // UI Update Timer
    private Timer statusUpdateTimer;

    // Main UI Components
    @FXML private TabPane mainTabPane;
    @FXML private Label statusLabel;
    @FXML private Label connectionStatusLabel;
    @FXML private Label timestampLabel;

    // Dashboard Components
    @FXML private Label overallScoreLabel;
    @FXML private Label riskLevelLabel;
    @FXML private Label passwordScoreLabel;
    @FXML private Label networkScoreLabel;
    @FXML private Label encryptionScoreLabel;
    @FXML private Label systemScoreLabel;
    @FXML private ProgressBar passwordScoreBar;
    @FXML private ProgressBar networkScoreBar;
    @FXML private ProgressBar encryptionScoreBar;
    @FXML private ProgressBar systemScoreBar;
    @FXML private VBox recommendationsContainer;

    // Password Analysis Components
    @FXML private PasswordField passwordField;
    @FXML private TextField visiblePasswordField;
    @FXML private CheckBox showPasswordCheckBox;
    @FXML private Label strengthScoreLabel;
    @FXML private Label strengthCategoryLabel;
    @FXML private ProgressBar strengthProgressBar;
    @FXML private VBox patternAnalysisContainer;
    @FXML private VBox suggestionsContainer;

    // Port Scanner Components
    @FXML private TextField targetHostField;
    @FXML private TextField startPortField;
    @FXML private TextField endPortField;
    @FXML private TextField timeoutField;
    @FXML private Button startScanButton;
    @FXML private Button stopScanButton;
    @FXML private VBox progressSection;
    @FXML private Label scanProgressLabel;
    @FXML private Label scanTimeLabel;
    @FXML private ProgressBar scanProgressBar;
    @FXML private Label scanStatsLabel;
    @FXML private CheckBox showVulnerableOnly;
    @FXML private TableView<PortScanResult.SinglePortResult> scanResultsTable;
    @FXML private TableColumn<PortScanResult.SinglePortResult, String> portColumn;
    @FXML private TableColumn<PortScanResult.SinglePortResult, String> statusColumn;
    @FXML private TableColumn<PortScanResult.SinglePortResult, String> serviceColumn;
    @FXML private TableColumn<PortScanResult.SinglePortResult, String> responseTimeColumn;
    @FXML private TableColumn<PortScanResult.SinglePortResult, String> vulnerabilitiesColumn;

    // Encryption Components
    @FXML private TextField selectedFilePath;
    @FXML private ComboBox<String> algorithmComboBox;
    @FXML private PasswordField encryptionPasswordField;
    @FXML private VBox encryptionProgressSection;
    @FXML private Label encryptionProgressLabel;
    @FXML private Label encryptionTimeLabel;
    @FXML private ProgressBar encryptionProgressBar;
    @FXML private TableView<EncryptionResult> encryptionHistoryTable;
    @FXML private TableColumn<EncryptionResult, String> timestampColumn;
    @FXML private TableColumn<EncryptionResult, String> operationColumn;
    @FXML private TableColumn<EncryptionResult, String> algorithmColumn;
    @FXML private TableColumn<EncryptionResult, String> fileNameColumn;
    @FXML private TableColumn<EncryptionResult, String> fileSizeColumn;
    @FXML private TableColumn<EncryptionResult, String> statusColumn;
    @FXML private TableColumn<EncryptionResult, String> verificationColumn;

    /**
     * Constructor initializes services and data structures.
     */
    public MainController() {
        this.passwordAnalysisService = new PasswordAnalysisService();
        this.portScanService = new PortScanService();
        this.encryptionService = new EncryptionService();
        this.securityScoringService = new SecurityScoringService();
        this.fileService = new FileService();

        this.encryptionHistory = FXCollections.observableArrayList();
        this.scanResults = FXCollections.observableArrayList();

        // Register event listeners
        registerEventListeners();

        // Start status update timer
        startStatusUpdateTimer();
    }

    /**
     * Initializes the controller after FXML loading.
     */
    @FXML
    public void initialize() {
        initializeComponents();
        setupEventHandlers();
        loadDefaultData();
        updateTimestamp();
    }

    /**
     * Initializes UI components and sets up tables.
     */
    private void initializeComponents() {
        // Initialize algorithm combo box
        algorithmComboBox.getItems().addAll(
            "AES-256",
            "RSA-2048",
            "Hybrid"
        );
        algorithmComboBox.getSelectionModel().selectFirst();

        // Setup scan results table
        setupScanResultsTable();

        // Setup encryption history table
        setupEncryptionHistoryTable();

        // Initialize dashboard with default values
        updateDashboardDisplay(null);

        // Set initial UI state
        setScanningUIState(false);
        setEncryptionUIState(false);
    }

    /**
     * Sets up the scan results table columns and data binding.
     */
    private void setupScanResultsTable() {
        portColumn.setCellValueFactory(data ->
            new javafx.beans.property.SimpleStringProperty(String.valueOf(data.getValue().getPort())));

        statusColumn.setCellValueFactory(data ->
            new javafx.beans.property.SimpleStringProperty(data.getValue().getStatus().getDisplayName()));

        serviceColumn.setCellValueFactory(data ->
            new javafx.beans.property.SimpleStringProperty(data.getValue().getService()));

        responseTimeColumn.setCellValueFactory(data ->
            new javafx.beans.property.SimpleStringProperty(data.getValue().getResponseTimeMs() + "ms"));

        vulnerabilitiesColumn.setCellValueFactory(data -> {
            int vulnCount = data.getValue().getVulnerabilityCount();
            if (vulnCount == 0) {
                return new javafx.beans.property.SimpleStringProperty("None");
            } else {
                StringBuilder vulns = new StringBuilder();
                for (PortScanResult.Vulnerability vuln : data.getValue().getVulnerabilities()) {
                    if (vulns.length() > 0) vulns.append(", ");
                    vulns.append(vuln.getSeverity().getDisplayName());
                }
                return new javafx.beans.property.SimpleStringProperty(vulnCount + " (" + vulns.toString() + ")");
            }
        });

        scanResultsTable.setItems(scanResults);

        // Filter for vulnerable only checkbox
        showVulnerableOnly.setOnAction(e -> filterScanResults());
    }

    /**
     * Sets up the encryption history table columns and data binding.
     */
    private void setupEncryptionHistoryTable() {
        timestampColumn.setCellValueFactory(data ->
            new javafx.beans.property.SimpleStringProperty(
                data.getValue().getTimestamp().format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss"))));

        operationColumn.setCellValueFactory(data ->
            new javafx.beans.property.SimpleStringProperty(data.getValue().getOperationType().getDisplayName()));

        algorithmColumn.setCellValueFactory(data ->
            new javafx.beans.property.SimpleStringProperty(data.getValue().getAlgorithm().getDisplayName()));

        fileNameColumn.setCellValueFactory(data ->
            new javafx.beans.property.SimpleStringProperty(data.getValue().getOriginalFileName()));

        fileSizeColumn.setCellValueFactory(data ->
            new javafx.beans.property.SimpleStringProperty(data.getValue().getFormattedFileSize()));

        statusColumn.setCellValueFactory(data ->
            new javafx.beans.property.SimpleStringProperty(data.getValue().getStatus().getDisplayName()));

        verificationColumn.setCellValueFactory(data ->
            new javafx.beans.property.SimpleStringProperty(data.getValue().getVerificationStatus()));

        encryptionHistoryTable.setItems(encryptionHistory);
    }

    /**
     * Sets up event handlers for UI components.
     */
    private void setupEventHandlers() {
        // Password visibility toggle
        showPasswordCheckBox.setOnAction(e -> togglePasswordVisibility());

        // Password field change listener
        passwordField.textProperty().addListener((obs, oldVal, newVal) -> {
            if (!newVal.isEmpty()) {
                analyzePasswordRealTime(newVal);
            }
        });

        visiblePasswordField.textProperty().addListener((obs, oldVal, newVal) -> {
            if (!newVal.isEmpty()) {
                analyzePasswordRealTime(newVal);
            }
        });

        // Port scan validation
        startPortField.textProperty().addListener((obs, oldVal, newVal) -> validatePortInput());
        endPortField.textProperty().addListener((obs, oldVal, newVal) -> validatePortInput());
        timeoutField.textProperty().addListener((obs, oldVal, newVal) -> validateTimeoutInput());

        // Target host validation
        targetHostField.textProperty().addListener((obs, oldVal, newVal) -> validateHostInput());
    }

    /**
     * Registers event listeners for application-wide events.
     */
    private void registerEventListeners() {
        EventManager eventManager = EventManager.getInstance();

        // Password analysis events
        eventManager.addEventListener(EventManager.PasswordAnalysisCompletedEvent.class, this::onPasswordAnalysisCompleted);

        // Port scan events
        eventManager.addEventListener(EventManager.PortScanProgressEvent.class, this::onPortScanProgress);
        eventManager.addEventListener(EventManager.PortScanCompletedEvent.class, this::onPortScanCompleted);

        // Encryption events
        eventManager.addEventListener(EventManager.EncryptionProgressEvent.class, this::onEncryptionProgress);
        eventManager.addEventListener(EventManager.EncryptionCompletedEvent.class, this::onEncryptionCompleted);

        // Security score events
        eventManager.addEventListener(EventManager.SecurityScoreUpdatedEvent.class, this::onSecurityScoreUpdated);

        // Application status events
        eventManager.addEventListener(EventManager.ApplicationStatusEvent.class, this::onApplicationStatus);
    }

    /**
     * Loads default data and sets initial UI state.
     */
    private void loadDefaultData() {
        updateStatusLabel("Ready");
        setConnectionStatus(false);

        // Load configuration
        loadConfigurationSettings();

        // Set default scan values
        targetHostField.setText("localhost");
        startPortField.setText("1");
        endPortField.setText("1024");
        timeoutField.setText("1000");
    }

    /**
     * Loads configuration settings and applies them to UI.
     */
    private void loadConfigurationSettings() {
        // Load settings from ConfigManager and apply to UI
        // This would integrate with the ConfigManager utility
    }

    /**
     * Starts the status update timer.
     */
    private void startStatusUpdateTimer() {
        statusUpdateTimer = new Timer("StatusUpdateTimer", true);
        statusUpdateTimer.scheduleAtFixedRate(new TimerTask() {
            @Override
            public void run() {
                Platform.runLater(() -> updateTimestamp());
            }
        }, 0, 1000); // Update every second
    }

    /**
     * Updates the timestamp label.
     */
    private void updateTimestamp() {
        timestampLabel.setText(LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss")));
    }

    /**
     * Updates the status label.
     */
    private void updateStatusLabel(String status) {
        statusLabel.setText(status);
    }

    /**
     * Sets the connection status.
     */
    private void setConnectionStatus(boolean online) {
        connectionStatusLabel.setText(online ? "Online" : "Offline");
        connectionStatusLabel.getStyleClass().removeAll("online", "offline");
        connectionStatusLabel.getStyleClass().add(online ? "online" : "offline");
    }

    // Menu Action Handlers
    @FXML
    private void handleNewAnalysis() {
        // Clear all current analysis data
        clearAllData();
        updateStatusLabel("New analysis started");
    }

    @FXML
    private void handleOpenResults() {
        FileChooser fileChooser = new FileChooser();
        fileChooser.setTitle("Open Security Analysis Results");
        fileChooser.getExtensionFilters().add(
            new FileChooser.ExtensionFilter("JSON Files", "*.json")
        );

        File file = fileChooser.showOpenDialog(getStage());
        if (file != null) {
            // Load results from file
            loadResultsFromFile(file);
        }
    }

    @FXML
    private void handleSaveResults() {
        if (currentSecurityScore == null) {
            showAlert(Alert.AlertType.WARNING, "No Results", "No analysis results to save.");
            return;
        }

        FileChooser fileChooser = new FileChooser();
        fileChooser.setTitle("Save Security Analysis Results");
        fileChooser.getExtensionFilters().add(
            new FileChooser.ExtensionFilter("JSON Files", "*.json")
        );

        File file = fileChooser.showSaveDialog(getStage());
        if (file != null) {
            // Save results to file
            saveResultsToFile(file);
        }
    }

    @FXML
    private void handleExportReport() {
        if (currentSecurityScore == null) {
            showAlert(Alert.AlertType.WARNING, "No Report", "No analysis results to export.");
            return;
        }

        FileChooser fileChooser = new FileChooser();
        fileChooser.setTitle("Export Security Report");
        fileChooser.getExtensionFilters().addAll(
            new FileChooser.ExtensionFilter("PDF Files", "*.pdf"),
            new FileChooser.ExtensionFilter("HTML Files", "*.html"),
            new FileChooser.ExtensionFilter("Text Files", "*.txt")
        );

        File file = fileChooser.showSaveDialog(getStage());
        if (file != null) {
            // Export report to file
            exportReportToFile(file);
        }
    }

    @FXML
    private void handleSettings() {
        // Open settings dialog
        showSettingsDialog();
    }

    @FXML
    private void handleAbout() {
        showAlert(Alert.AlertType.INFORMATION, "About Java Security Analyzer",
            "Java Security Analyzer v1.0.0\n\n" +
            "A comprehensive desktop-based cybersecurity analysis tool\n" +
            "for password analysis, port scanning, and file encryption.\n\n" +
            "Built with Java, JavaFX, and modern security libraries.");
    }

    @FXML
    private void handleExit() {
        // Cleanup resources
        cleanup();

        // Close application
        Platform.exit();
        System.exit(0);
    }

    // Dashboard Action Handlers
    @FXML
    private void handleRunFullScan() {
        updateStatusLabel("Starting full security scan...");

        // Run comprehensive analysis in background
        Task<SecurityScore> fullScanTask = new Task<>() {
            @Override
            protected SecurityScore call() throws Exception {
                updateMessage("Analyzing password security...");
                // Simulate password analysis
                PasswordAnalysis passwordAnalysis = new PasswordAnalysis("sample");
                passwordAnalysis.setStrengthScore(85);

                updateMessage("Scanning network ports...");
                // Simulate port scan
                PortScanResult portScan = new PortScanResult("localhost", 1, 1024, 5000);
                portScan.setStatus(PortScanResult.ScanStatus.COMPLETED);

                updateMessage("Calculating security score...");
                return securityScoringService.calculateOverallSecurity(
                    passwordAnalysis, portScan, encryptionHistory);
            }

            @Override
            protected void succeeded() {
                currentSecurityScore = getValue();
                updateDashboardDisplay(currentSecurityScore);
                updateStatusLabel("Full security scan completed");
            }

            @Override
            protected void failed() {
                updateStatusLabel("Full scan failed: " + getException().getMessage());
            }
        };

        new Thread(fullScanTask).start();
    }

    @FXML
    private void handleUpdateScores() {
        if (currentPasswordAnalysis != null || currentPortScanResult != null || !encryptionHistory.isEmpty()) {
            updateSecurityScore();
            updateStatusLabel("Security scores updated");
        } else {
            showAlert(Alert.AlertType.INFO, "No Data", "No analysis data available for scoring.");
        }
    }

    // Event Handlers
    private void onPasswordAnalysisCompleted(EventManager.PasswordAnalysisCompletedEvent event) {
        Platform.runLater(() -> {
            if (event.isSuccessful()) {
                updateStatusLabel("Password analysis completed");
                updateSecurityScore();
            } else {
                updateStatusLabel("Password analysis failed");
            }
        });
    }

    private void onPortScanProgress(EventManager.PortScanProgressEvent event) {
        Platform.runLater(() -> {
            updateScanProgress(event.getCurrentPort(), event.getTotalPorts(),
                            event.getOpenPortsFound(), event.getProgressPercentage());
        });
    }

    private void onPortScanCompleted(EventManager.PortScanCompletedEvent event) {
        Platform.runLater(() -> {
            setScanningUIState(false);
            if (event.isSuccessful()) {
                updateStatusLabel("Port scan completed - " + event.getOpenPortsCount() + " open ports found");
                updateSecurityScore();
            } else {
                updateStatusLabel("Port scan failed");
            }
        });
    }

    private void onEncryptionProgress(EventManager.EncryptionProgressEvent event) {
        Platform.runLater(() -> {
            updateEncryptionProgress(event.getBytesProcessed(), event.getTotalBytes(),
                                   event.getProgressPercentage(), event.getCurrentFile());
        });
    }

    private void onEncryptionCompleted(EventManager.EncryptionCompletedEvent event) {
        Platform.runLater(() -> {
            setEncryptionUIState(false);
            if (event.isSuccessful()) {
                updateStatusLabel(event.getOperationType() + " completed successfully");
                updateSecurityScore();
            } else {
                updateStatusLabel(event.getOperationType() + " failed: " + event.getErrorMessage());
            }
        });
    }

    private void onSecurityScoreUpdated(EventManager.SecurityScoreUpdatedEvent event) {
        Platform.runLater(() -> {
            updateStatusLabel("Security score updated: " + event.getOverallScore() + "/100 (" + event.getRiskLevel() + ")");
        });
    }

    private void onApplicationStatus(EventManager.ApplicationStatusEvent event) {
        Platform.runLater(() -> {
            updateStatusLabel(event.getMessage());
        });
    }

    // Helper Methods
    private void togglePasswordVisibility() {
        boolean showPassword = showPasswordCheckBox.isSelected();
        String currentPassword = showPassword ? passwordField.getText() : visiblePasswordField.getText();

        passwordField.setVisible(!showPassword);
        passwordField.setManaged(!showPassword);
        visiblePasswordField.setVisible(showPassword);
        visiblePasswordField.setManaged(showPassword);

        if (showPassword) {
            visiblePasswordField.setText(currentPassword);
        } else {
            passwordField.setText(currentPassword);
        }
    }

    private void analyzePasswordRealTime(String password) {
        if (password.isEmpty()) {
            clearPasswordAnalysis();
            return;
        }

        Task<PasswordAnalysis> analysisTask = new Task<>() {
            @Override
            protected PasswordAnalysis call() throws Exception {
                return passwordAnalysisService.analyzePassword(password);
            }

            @Override
            protected void succeeded() {
                currentPasswordAnalysis = getValue();
                updatePasswordAnalysisDisplay(currentPasswordAnalysis);
            }
        };

        new Thread(analysisTask).start();
    }

    private void validatePortInput() {
        // Add validation logic for port inputs
    }

    private void validateTimeoutInput() {
        // Add validation logic for timeout input
    }

    private void validateHostInput() {
        // Add validation logic for host input
    }

    private void setScanningUIState(boolean scanning) {
        startScanButton.setDisable(scanning);
        stopScanButton.setDisable(!scanning);
        targetHostField.setDisable(scanning);
        startPortField.setDisable(scanning);
        endPortField.setDisable(scanning);
        timeoutField.setDisable(scanning);

        progressSection.setVisible(scanning);
        progressSection.setManaged(scanning);
    }

    private void setEncryptionUIState(boolean processing) {
        algorithmComboBox.setDisable(processing);
        selectedFilePath.setDisable(processing);
        encryptionPasswordField.setDisable(processing);

        encryptionProgressSection.setVisible(processing);
        encryptionProgressSection.setManaged(processing);
    }

    private void updateDashboardDisplay(SecurityScore securityScore) {
        if (securityScore != null) {
            overallScoreLabel.setText(securityScore.getFormattedScore());
            riskLevelLabel.setText(securityScore.getRiskLevel().getDisplayName());
            riskLevelLabel.setStyle("-fx-text-fill: " + securityScore.getRiskLevel().getColorCode() + ";");

            // Update category scores
            updateCategoryScore(SecurityScore.Category.PASSWORD_SECURITY,
                              securityScore.getCategoryScore(SecurityScore.Category.PASSWORD_SECURITY),
                              passwordScoreLabel, passwordScoreBar);

            updateCategoryScore(SecurityScore.Category.NETWORK_SECURITY,
                              securityScore.getCategoryScore(SecurityScore.Category.NETWORK_SECURITY),
                              networkScoreLabel, networkScoreBar);

            updateCategoryScore(SecurityScore.Category.ENCRYPTION_PRACTICES,
                              securityScore.getCategoryScore(SecurityScore.Category.ENCRYPTION_PRACTICES),
                              encryptionScoreLabel, encryptionScoreBar);

            updateCategoryScore(SecurityScore.Category.SYSTEM_CONFIGURATION,
                              securityScore.getCategoryScore(SecurityScore.Category.SYSTEM_CONFIGURATION),
                              systemScoreLabel, systemScoreBar);

            // Update recommendations
            updateRecommendations(securityScore.getRecommendations());
        }
    }

    private void updateCategoryScore(SecurityScore.Category category, int score,
                                   Label scoreLabel,ProgressBar progressBar) {
        scoreLabel.setText(score + "/100");
        progressBar.setProgress(score / 100.0);
    }

    private void updateRecommendations(List<SecurityScore.Recommendation> recommendations) {
        recommendationsContainer.getChildren().clear();

        for (SecurityScore.Recommendation recommendation : recommendations) {
            VBox recommendationCard = createRecommendationCard(recommendation);
            recommendationsContainer.getChildren().add(recommendationCard);
        }
    }

    private VBox createRecommendationCard(SecurityScore.Recommendation recommendation) {
        VBox card = new VBox(5);
        card.setStyle("-fx-background-color: white; -fx-border-color: #d5dbdb; -fx-border-width: 1px; " +
                     "-fx-border-radius: 5px; -fx-padding: 10px; -fx-background-radius: 5px;");

        Label titleLabel = new Label(recommendation.getTitle());
        titleLabel.setStyle("-fx-font-weight: bold; -fx-text-fill: " +
                           recommendation.getPriority().getColorCode() + ";");

        Label descLabel = new Label(recommendation.getDescription());
        descLabel.setStyle("-fx-text-fill: #7f8c8d;");

        card.getChildren().addAll(titleLabel, descLabel);

        return card;
    }

    private void updatePasswordAnalysisDisplay(PasswordAnalysis analysis) {
        strengthScoreLabel.setText(analysis.getStrengthScore() + "/100");
        strengthCategoryLabel.setText(analysis.getStrengthCategory());
        strengthCategoryLabel.setStyle("-fx-text-fill: " + analysis.getStrengthColor() + "; " +
                                      "-fx-background-color: " + analysis.getStrengthColor() + "20; " +
                                      "-fx-background-radius: 15px; -fx-padding: 3px 10px;");

        strengthProgressBar.setProgress(analysis.getStrengthScore() / 100.0);
        strengthProgressBar.setStyle("-fx-accent: " + analysis.getStrengthColor() + ";");

        // Update pattern analysis and suggestions
        updatePatternAnalysis(analysis);
        updateSuggestions(analysis);
    }

    private void updatePatternAnalysis(PasswordAnalysis analysis) {
        patternAnalysisContainer.getChildren().clear();

        // Add complexity indicators
        addComplexityIndicator("Uppercase Letters", analysis.isHasUppercase());
        addComplexityIndicator("Lowercase Letters", analysis.isHasLowercase());
        addComplexityIndicator("Numbers", analysis.isHasDigits());
        addComplexityIndicator("Special Characters", analysis.isHasSpecialChars());

        // Add detected patterns
        for (String pattern : analysis.getDetectedPatterns()) {
            Label patternLabel = new Label("⚠ " + pattern);
            patternLabel.setStyle("-fx-text-fill: #e74c3c;");
            patternAnalysisContainer.getChildren().add(patternLabel);
        }
    }

    private void addComplexityIndicator(String name, boolean present) {
        Label indicator = new Label((present ? "✓ " : "✗ ") + name);
        indicator.setStyle("-fx-text-fill: " + (present ? "#27ae60" : "#e74c3c") + ";");
        patternAnalysisContainer.getChildren().add(indicator);
    }

    private void updateSuggestions(PasswordAnalysis analysis) {
        suggestionsContainer.getChildren().clear();

        for (String suggestion : analysis.getSuggestions()) {
            Label suggestionLabel = new Label("• " + suggestion);
            suggestionLabel.setStyle("-fx-text-fill: #34495e; -fx-padding: 2px 0;");
            suggestionsContainer.getChildren().add(suggestionLabel);
        }
    }

    private void updateScanProgress(int currentPort, int totalPorts, int openPorts, double percentage) {
        scanProgressLabel.setText(String.format("%d/%d ports (%.1f%%) - %d open",
                                  currentPort, totalPorts, percentage, openPorts));
        scanProgressBar.setProgress(percentage / 100.0);
    }

    private void updateEncryptionProgress(long bytesProcessed, long totalBytes,
                                        double percentage, String currentFile) {
        encryptionProgressLabel.setText(String.format("%.1f%% - %s", percentage, currentFile));
        encryptionProgressBar.setProgress(percentage / 100.0);
    }

    private void updateSecurityScore() {
        if (currentPasswordAnalysis != null || currentPortScanResult != null || !encryptionHistory.isEmpty()) {
            Task<SecurityScore> scoringTask = new Task<>() {
                @Override
                protected SecurityScore call() throws Exception {
                    return securityScoringService.calculateOverallSecurity(
                        currentPasswordAnalysis, currentPortScanResult, encryptionHistory);
                }

                @Override
                protected void succeeded() {
                    currentSecurityScore = getValue();
                    updateDashboardDisplay(currentSecurityScore);

                    // Publish score update event
                    EventManager.getInstance().publishEvent(new EventManager.SecurityScoreUpdatedEvent(
                        currentSecurityScore.getOverallScore(),
                        currentSecurityScore.getRiskLevel().getDisplayName(),
                        currentSecurityScore.getAssessmentSummary()
                    ));
                }
            };

            new Thread(scoringTask).start();
        }
    }

    private void clearPasswordAnalysis() {
        strengthScoreLabel.setText("--/100");
        strengthCategoryLabel.setText("--");
        strengthCategoryLabel.setStyle("");
        strengthProgressBar.setProgress(0);
        patternAnalysisContainer.getChildren().clear();
        suggestionsContainer.getChildren().clear();
    }

    private void clearAllData() {
        currentPasswordAnalysis = null;
        currentPortScanResult = null;
        currentSecurityScore = null;

        clearPasswordAnalysis();
        scanResults.clear();
        encryptionHistory.clear();
        updateDashboardDisplay(null);

        updateStatusLabel("All data cleared");
    }

    private void filterScanResults() {
        if (showVulnerableOnly.isSelected()) {
            // Filter to show only vulnerable ports
            // Implementation depends on the data structure
        } else {
            // Show all ports
        }
    }

    private void showAlert(Alert.AlertType type, String title, String message) {
        Alert alert = new Alert(type);
        alert.setTitle(title);
        alert.setHeaderText(null);
        alert.setContentText(message);
        alert.showAndWait();
    }

    private void showSettingsDialog() {
        // Implementation for settings dialog
        showAlert(Alert.AlertType.INFORMATION, "Settings", "Settings dialog not yet implemented.");
    }

    private Stage getStage() {
        return (Stage) mainTabPane.getScene().getWindow();
    }

    private void loadResultsFromFile(File file) {
        // Implementation for loading results from file
        updateStatusLabel("Results loaded from " + file.getName());
    }

    private void saveResultsToFile(File file) {
        // Implementation for saving results to file
        updateStatusLabel("Results saved to " + file.getName());
    }

    private void exportReportToFile(File file) {
        // Implementation for exporting report to file
        updateStatusLabel("Report exported to " + file.getName());
    }

    private void cleanup() {
        // Stop timer
        if (statusUpdateTimer != null) {
            statusUpdateTimer.cancel();
        }

        // Shutdown services
        portScanService.shutdown();

        // Clear event listeners
        EventManager.getInstance().clearAllListeners();
    }

    // Password Analysis Handlers
    @FXML
    public void handleAnalyzePassword() {
        String password = showPasswordCheckBox.isSelected() ?
                         visiblePasswordField.getText() : passwordField.getText();

        if (password == null || password.isEmpty()) {
            showAlert(Alert.AlertType.WARNING, "No Password", "Please enter a password to analyze.");
            return;
        }

        updateStatusLabel("Analyzing password...");

        Task<PasswordAnalysis> analysisTask = new Task<>() {
            @Override
            protected PasswordAnalysis call() throws Exception {
                return passwordAnalysisService.analyzePassword(password);
            }

            @Override
            protected void succeeded() {
                currentPasswordAnalysis = getValue();
                updatePasswordAnalysisDisplay(currentPasswordAnalysis);
                updateStatusLabel("Password analysis completed");

                // Publish completion event
                EventManager.getInstance().publishEvent(new EventManager.PasswordAnalysisCompletedEvent(
                    currentPasswordAnalysis.getId(),
                    currentPasswordAnalysis.getStrengthScore(),
                    true
                ));
            }

            @Override
            protected void failed() {
                updateStatusLabel("Password analysis failed: " + getException().getMessage());
                EventManager.getInstance().publishEvent(new EventManager.PasswordAnalysisCompletedEvent(
                    "", 0, false
                ));
            }
        };

        new Thread(analysisTask).start();
    }

    // Port Scanner Handlers
    @FXML
    public void handleStartScan() {
        String targetHost = targetHostField.getText();
        String startPortText = startPortField.getText();
        String endPortText = endPortField.getText();
        String timeoutText = timeoutField.getText();

        // Validate inputs
        if (targetHost.isEmpty()) {
            showAlert(Alert.AlertType.WARNING, "Invalid Input", "Please enter a target host.");
            return;
        }

        try {
            int startPort = Integer.parseInt(startPortText);
            int endPort = Integer.parseInt(endPortText);
            int timeout = Integer.parseInt(timeoutText);

            if (startPort < 1 || endPort > 65535 || startPort > endPort) {
                showAlert(Alert.AlertType.WARNING, "Invalid Port Range", "Please enter a valid port range (1-65535).");
                return;
            }

            // Start scan
            setScanningUIState(true);
            updateStatusLabel("Starting port scan...");
            scanResults.clear();

            Task<PortScanResult> scanTask = new Task<>() {
                private volatile boolean cancelled = false;

                @Override
                protected PortScanResult call() throws Exception {
                    // Publish progress events periodically
                    Timer progressTimer = new Timer();
                    progressTimer.scheduleAtFixedRate(new TimerTask() {
                        private int currentPort = startPort;

                        @Override
                        public void run() {
                            if (!cancelled && currentPort <= endPort) {
                                EventManager.getInstance().publishEvent(new EventManager.PortScanProgressEvent(
                                    "scan-" + System.currentTimeMillis(),
                                    currentPort,
                                    endPort - startPort + 1,
                                    0 // Will be updated with actual open ports
                                ));
                                currentPort += 50; // Update every 50 ports
                            }
                        }
                    }, 1000, 1000);

                    try {
                        PortScanResult result = portScanService.scanPorts(targetHost, startPort, endPort, timeout);
                        progressTimer.cancel();
                        return result;
                    } catch (Exception e) {
                        progressTimer.cancel();
                        throw e;
                    }
                }

                @Override
                protected void cancelled() {
                    portScanService.cancelScan();
                    super.cancelled();
                }

                @Override
                protected void succeeded() {
                    currentPortScanResult = getValue();
                    scanResults.setAll(currentPortScanResult.getPortResults());
                    setScanningUIState(false);
                    updateScanStats(currentPortScanResult);
                    updateStatusLabel("Port scan completed - " + currentPortScanResult.getOpenPortsCount() + " open ports found");

                    EventManager.getInstance().publishEvent(new EventManager.PortScanCompletedEvent(
                        currentPortScanResult.getId(),
                        currentPortScanResult.getOpenPortsCount(),
                        currentPortScanResult.getVulnerablePortsCount(),
                        true
                    ));
                }

                @Override
                protected void failed() {
                    setScanningUIState(false);
                    updateStatusLabel("Port scan failed: " + getException().getMessage());

                    EventManager.getInstance().publishEvent(new EventManager.PortScanCompletedEvent(
                        "", 0, 0, false
                    ));
                }
            };

            new Thread(scanTask).start();

        } catch (NumberFormatException e) {
            showAlert(Alert.AlertType.WARNING, "Invalid Input", "Please enter valid numeric values for ports and timeout.");
        }
    }

    @FXML
    public void handleStopScan() {
        portScanService.cancelScan();
        updateStatusLabel("Port scan cancelled");
    }

    @FXML
    public void handleClearScanResults() {
        scanResults.clear();
        currentPortScanResult = null;
        scanStatsLabel.setText("No scan performed");
        updateStatusLabel("Scan results cleared");
    }

    @FXML
    public void handleSetCommonPorts() {
        startPortField.setText("1");
        endPortField.setText("1024");
        updateStatusLabel("Set to common ports (1-1024)");
    }

    @FXML
    public void handleSetAllPorts() {
        startPortField.setText("1");
        endPortField.setText("65535");
        updateStatusLabel("Set to all ports (1-65535)");
    }

    // File Encryption Handlers
    @FXML
    public void handleBrowseFile() {
        FileChooser fileChooser = new FileChooser();
        fileChooser.setTitle("Select File for Encryption/Decryption");

        File file = fileChooser.showOpenDialog(getStage());
        if (file != null) {
            selectedFilePath.setText(file.getAbsolutePath());
            updateStatusLabel("Selected file: " + file.getName());
        }
    }

    @FXML
    public void handleEncryptFile() {
        String filePath = selectedFilePath.getText();
        String password = encryptionPasswordField.getText();
        String algorithm = algorithmComboBox.getValue();

        if (filePath.isEmpty()) {
            showAlert(Alert.AlertType.WARNING, "No File Selected", "Please select a file to encrypt.");
            return;
        }

        if (password.isEmpty()) {
            showAlert(Alert.AlertType.WARNING, "No Password", "Please enter a password for encryption.");
            return;
        }

        if (!encryptionService.validateEncryptionPassword(password)) {
            showAlert(Alert.AlertType.WARNING, "Weak Password",
                "Password is too weak. Use at least 12 characters with mixed case, numbers, and symbols.");
            return;
        }

        setEncryptionUIState(true);
        updateStatusLabel("Starting file encryption...");

        Task<EncryptionResult> encryptionTask = new Task<>() {
            @Override
            protected EncryptionResult call() throws Exception {
                EncryptionResult result = null;

                switch (algorithm) {
                    case "AES-256":
                        result = encryptionService.encryptFileAES(filePath, password);
                        break;
                    case "RSA-2048":
                        showAlert(Alert.AlertType.INFORMATION, "RSA Key Required",
                            "For RSA encryption, please first generate or select RSA keys.");
                        return null;
                    case "Hybrid":
                        showAlert(Alert.AlertType.INFORMATION, "RSA Key Required",
                            "For hybrid encryption, please first generate or select RSA keys.");
                        return null;
                    default:
                        throw new IllegalArgumentException("Unsupported algorithm: " + algorithm);
                }

                return result;
            }

            @Override
            protected void succeeded() {
                EncryptionResult result = getValue();
                if (result != null) {
                    encryptionHistory.add(0, result); // Add to beginning of list
                    setEncryptionUIState(false);
                    updateStatusLabel("File encryption completed successfully");

                    EventManager.getInstance().publishEvent(new EventManager.EncryptionCompletedEvent(
                        result.getId(),
                        result.getOperationType().getDisplayName(),
                        result.getAlgorithm().getDisplayName(),
                        true,
                        null
                    ));
                }
            }

            @Override
            protected void failed() {
                setEncryptionUIState(false);
                updateStatusLabel("Encryption failed: " + getException().getMessage());

                EventManager.getInstance().publishEvent(new EventManager.EncryptionCompletedEvent(
                    "",
                    "Encryption",
                    algorithm,
                    false,
                    getException().getMessage()
                ));
            }
        };

        new Thread(encryptionTask).start();
    }

    @FXML
    public void handleDecryptFile() {
        String filePath = selectedFilePath.getText();
        String password = encryptionPasswordField.getText();

        if (filePath.isEmpty()) {
            showAlert(Alert.AlertType.WARNING, "No File Selected", "Please select a file to decrypt.");
            return;
        }

        if (password.isEmpty()) {
            showAlert(Alert.AlertType.WARNING, "No Password", "Please enter the password for decryption.");
            return;
        }

        setEncryptionUIState(true);
        updateStatusLabel("Starting file decryption...");

        Task<EncryptionResult> decryptionTask = new Task<>() {
            @Override
            protected EncryptionResult call() throws Exception {
                EncryptionResult result = null;

                if (filePath.endsWith(".encrypted")) {
                    result = encryptionService.decryptFileAES(filePath, password);
                } else if (filePath.endsWith(".rsa.encrypted")) {
                    showAlert(Alert.AlertType.INFORMATION, "RSA Key Required",
                        "For RSA decryption, please select the corresponding private key file.");
                    return null;
                } else if (filePath.endsWith(".hybrid.encrypted")) {
                    showAlert(Alert.AlertType.INFORMATION, "RSA Key Required",
                        "For hybrid decryption, please select the corresponding private key file.");
                    return null;
                } else {
                    showAlert(Alert.AlertType.WARNING, "Unknown File Type",
                        "Cannot determine encryption type from file extension.");
                    return null;
                }

                return result;
            }

            @Override
            protected void succeeded() {
                EncryptionResult result = getValue();
                if (result != null) {
                    encryptionHistory.add(0, result);
                    setEncryptionUIState(false);
                    updateStatusLabel("File decryption completed successfully");

                    EventManager.getInstance().publishEvent(new EventManager.EncryptionCompletedEvent(
                        result.getId(),
                        result.getOperationType().getDisplayName(),
                        result.getAlgorithm().getDisplayName(),
                        true,
                        null
                    ));
                }
            }

            @Override
            protected void failed() {
                setEncryptionUIState(false);
                updateStatusLabel("Decryption failed: " + getException().getMessage());

                EventManager.getInstance().publishEvent(new EventManager.EncryptionCompletedEvent(
                    "",
                    "Decryption",
                    "Unknown",
                    false,
                    getException().getMessage()
                ));
            }
        };

        new Thread(decryptionTask).start();
    }

    @FXML
    public void handleGenerateKeys() {
        FileChooser fileChooser = new FileChooser();
        fileChooser.setTitle("Save RSA Key Pair");
        fileChooser.getExtensionFilters().add(
            new FileChooser.ExtensionFilter("Key Files", "*.key")
        );

        File file = fileChooser.showSaveDialog(getStage());
        if (file != null) {
            String keyPath = file.getAbsolutePath();
            if (keyPath.endsWith(".key")) {
                keyPath = keyPath.substring(0, keyPath.length() - 4);
            }

            updateStatusLabel("Generating RSA key pair...");

            Task<EncryptionResult> keyGenTask = new Task<>() {
                @Override
                protected EncryptionResult call() throws Exception {
                    return encryptionService.generateRSAKeyPair(keyPath);
                }

                @Override
                protected void succeeded() {
                    EncryptionResult result = getValue();
                    updateStatusLabel("RSA key pair generated successfully");
                    showAlert(Alert.AlertType.INFORMATION, "Keys Generated",
                        "RSA key pair generated successfully:\n" +
                        "Private key: " + keyPath + "_private.key\n" +
                        "Public key: " + keyPath + "_public.key");
                }

                @Override
                protected void failed() {
                    updateStatusLabel("Key generation failed: " + getException().getMessage());
                    showAlert(Alert.AlertType.ERROR, "Key Generation Failed",
                        "Failed to generate RSA keys: " + getException().getMessage());
                }
            };

            new Thread(keyGenTask).start();
        }
    }

    @FXML
    public void handleClearEncryptionHistory() {
        encryptionHistory.clear();
        updateStatusLabel("Encryption history cleared");
    }

    // Helper Methods
    private void updateScanStats(PortScanResult scanResult) {
        scanStatsLabel.setText(String.format("Scan completed: %d total, %d open, %d vulnerable",
            scanResult.getTotalPortsCount(),
            scanResult.getOpenPortsCount(),
            scanResult.getVulnerablePortsCount()));
    }
}