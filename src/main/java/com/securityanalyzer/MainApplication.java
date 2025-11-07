package com.securityanalyzer;

import javafx.application.Application;
import javafx.fxml.FXMLLoader;
import javafx.scene.Scene;
import javafx.scene.image.Image;
import javafx.stage.Stage;

import java.io.IOException;
import java.util.Objects;

/**
 * Main entry point for the Java Security Analyzer application.
 * Extends JavaFX Application class and sets up the primary stage.
 */
public class MainApplication extends Application {

    private static final String APP_TITLE = "Java Security Analyzer";
    private static final String MAIN_FXML_PATH = "/fxml/main_dashboard.fxml";
    private static final String CSS_PATH = "/css/main.css";
    private static final double MIN_WIDTH = 800;
    private static final double MIN_HEIGHT = 600;
    private static final double DEFAULT_WIDTH = 1200;
    private static final double DEFAULT_HEIGHT = 800;

    @Override
    public void start(Stage stage) throws IOException {
        try {
            // Load the main FXML layout
            FXMLLoader fxmlLoader = new FXMLLoader(MainApplication.class.getResource(MAIN_FXML_PATH));
            Scene scene = new Scene(fxmlLoader.load(), DEFAULT_WIDTH, DEFAULT_HEIGHT);

            // Load and apply CSS styling
            scene.getStylesheets().add(Objects.requireNonNull(MainApplication.class.getResource(CSS_PATH)).toExternalForm());

            // Configure the primary stage
            setupStage(stage, scene);

            // Show the application
            stage.show();

        } catch (IOException e) {
            System.err.println("Failed to load application: " + e.getMessage());
            throw e;
        }
    }

    /**
     * Configures the primary stage with basic settings.
     *
     * @param stage The primary stage to configure
     * @param scene The main scene to display
     */
    private void setupStage(Stage stage, Scene scene) {
        // Set window properties
        stage.setTitle(APP_TITLE);
        stage.setScene(scene);
        stage.setMinWidth(MIN_WIDTH);
        stage.setMinHeight(MIN_HEIGHT);

        // Try to set application icon
        try {
            Image icon = new Image(Objects.requireNonNull(MainApplication.class.getResourceAsStream("/images/app-icon.png")));
            stage.getIcons().add(icon);
        } catch (Exception e) {
            // Icon not found, continue without it
            System.err.println("Application icon not found, continuing without icon");
        }

        // Handle window close event
        stage.setOnCloseRequest(event -> {
            // Perform any cleanup before closing
            performCleanup();
            stage.close();
        });
    }

    /**
     * Performs cleanup operations when the application is closing.
     */
    private void performCleanup() {
        // TODO: Add cleanup logic here
        // - Save user preferences
        // - Close network connections
        // - Clear sensitive data from memory
        // - Log application shutdown
    }

    /**
     * Main method - entry point for the application.
     *
     * @param args Command line arguments
     */
    public static void main(String[] args) {
        launch(args);
    }
}