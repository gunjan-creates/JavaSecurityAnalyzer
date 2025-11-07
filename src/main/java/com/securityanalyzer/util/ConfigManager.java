package com.securityanalyzer.util;

import java.io.*;
import java.util.Properties;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

/**
 * Configuration manager for application settings and user preferences.
 * Handles loading, saving, and managing configuration properties.
 */
public class ConfigManager {

    private static final String CONFIG_FILE_NAME = "security-analyzer.properties";
    private static final String DEFAULT_CONFIG_DIR = System.getProperty("user.home") + File.separator + ".security-analyzer";

    private static ConfigManager instance;
    private final Properties properties;
    private final File configFile;
    private final ConcurrentMap<String, Object> runtimeCache;

    private ConfigManager() {
        this.properties = new Properties();
        this.runtimeCache = new ConcurrentHashMap<>();
        this.configFile = new File(DEFAULT_CONFIG_DIR, CONFIG_FILE_NAME);

        loadConfiguration();
        setDefaultValues();
    }

    /**
     * Gets the singleton instance of ConfigManager.
     */
    public static synchronized ConfigManager getInstance() {
        if (instance == null) {
            instance = new ConfigManager();
        }
        return instance;
    }

    /**
     * Loads configuration from file.
     */
    private void loadConfiguration() {
        try {
            if (configFile.exists()) {
                try (FileInputStream fis = new FileInputStream(configFile)) {
                    properties.load(fis);
                }
            }
        } catch (IOException e) {
            System.err.println("Failed to load configuration: " + e.getMessage());
        }
    }

    /**
     * Sets default values for configuration properties.
     */
    private void setDefaultValues() {
        // Port Scanner Settings
        setPropertyIfNotExists("scanner.default.timeout", "1000");
        setPropertyIfNotExists("scanner.default.startPort", "1");
        setPropertyIfNotExists("scanner.default.endPort", "1024");
        setPropertyIfNotExists("scanner.threadPoolSize", "20");
        setPropertyIfNotExists("scanner.maxConcurrentThreads", "50");

        // Password Analysis Settings
        setPropertyIfNotExists("password.minLength", "8");
        setPropertyIfNotExists("password.maxLength", "128");
        setPropertyIfNotExists("password.requireUppercase", "true");
        setPropertyIfNotExists("password.requireLowercase", "true");
        setPropertyIfNotExists("password.requireDigits", "true");
        setPropertyIfNotExists("password.requireSpecialChars", "true");

        // Encryption Settings
        setPropertyIfNotExists("encryption.defaultAlgorithm", "AES_256");
        setPropertyIfNotExists("encryption.keyDerivationIterations", "100000");
        setPropertyIfNotExists("encryption.tempDirectory", System.getProperty("java.io.tmpdir"));

        // UI Settings
        setPropertyIfNotExists("ui.theme", "default");
        setPropertyIfNotExists("ui.windowWidth", "1200");
        setPropertyIfNotExists("ui.windowHeight", "800");
        setPropertyIfNotExists("ui.showAdvancedOptions", "false");

        // Security Scoring Settings
        setPropertyIfNotExists("scoring.passwordWeight", "30");
        setPropertyIfNotExists("scoring.networkWeight", "40");
        setPropertyIfNotExists("scoring.encryptionWeight", "20");
        setPropertyIfNotExists("scoring.systemWeight", "10");

        // Logging Settings
        setPropertyIfNotExists("logging.level", "INFO");
        setPropertyIfNotExists("logging.fileEnabled", "true");
        setPropertyIfNotExists("logging.maxFileSize", "10MB");
        setPropertyIfNotExists("logging.maxFiles", "5");

        // General Settings
        setPropertyIfNotExists("general.autoSave", "true");
        setPropertyIfNotExists("general.checkUpdates", "true");
        setPropertyIfNotExists("general.firstRun", "true");
    }

    /**
     * Sets a property only if it doesn't already exist.
     */
    private void setPropertyIfNotExists(String key, String defaultValue) {
        if (properties.getProperty(key) == null) {
            properties.setProperty(key, defaultValue);
        }
    }

    /**
     * Gets a string property value.
     */
    public String getProperty(String key) {
        return properties.getProperty(key);
    }

    /**
     * Gets a string property value with a default.
     */
    public String getProperty(String key, String defaultValue) {
        return properties.getProperty(key, defaultValue);
    }

    /**
     * Gets an integer property value.
     */
    public int getIntProperty(String key) {
        return getIntProperty(key, 0);
    }

    /**
     * Gets an integer property value with a default.
     */
    public int getIntProperty(String key, int defaultValue) {
        try {
            String value = properties.getProperty(key);
            if (value != null) {
                return Integer.parseInt(value.trim());
            }
        } catch (NumberFormatException e) {
            System.err.println("Invalid integer value for key '" + key + "': " + properties.getProperty(key));
        }
        return defaultValue;
    }

    /**
     * Gets a long property value.
     */
    public long getLongProperty(String key) {
        return getLongProperty(key, 0L);
    }

    /**
     * Gets a long property value with a default.
     */
    public long getLongProperty(String key, long defaultValue) {
        try {
            String value = properties.getProperty(key);
            if (value != null) {
                return Long.parseLong(value.trim());
            }
        } catch (NumberFormatException e) {
            System.err.println("Invalid long value for key '" + key + "': " + properties.getProperty(key));
        }
        return defaultValue;
    }

    /**
     * Gets a boolean property value.
     */
    public boolean getBooleanProperty(String key) {
        return getBooleanProperty(key, false);
    }

    /**
     * Gets a boolean property value with a default.
     */
    public boolean getBooleanProperty(String key, boolean defaultValue) {
        String value = properties.getProperty(key);
        if (value != null) {
            return "true".equalsIgnoreCase(value.trim());
        }
        return defaultValue;
    }

    /**
     * Gets a double property value.
     */
    public double getDoubleProperty(String key) {
        return getDoubleProperty(key, 0.0);
    }

    /**
     * Gets a double property value with a default.
     */
    public double getDoubleProperty(String key, double defaultValue) {
        try {
            String value = properties.getProperty(key);
            if (value != null) {
                return Double.parseDouble(value.trim());
            }
        } catch (NumberFormatException e) {
            System.err.println("Invalid double value for key '" + key + "': " + properties.getProperty(key));
        }
        return defaultValue;
    }

    /**
     * Sets a property value.
     */
    public void setProperty(String key, String value) {
        if (key != null && value != null) {
            properties.setProperty(key, value);
            runtimeCache.remove(key); // Clear cached value
        }
    }

    /**
     * Sets an integer property value.
     */
    public void setProperty(String key, int value) {
        setProperty(key, String.valueOf(value));
    }

    /**
     * Sets a long property value.
     */
    public void setProperty(String key, long value) {
        setProperty(key, String.valueOf(value));
    }

    /**
     * Sets a boolean property value.
     */
    public void setProperty(String key, boolean value) {
        setProperty(key, String.valueOf(value));
    }

    /**
     * Sets a double property value.
     */
    public void setProperty(String key, double value) {
        setProperty(key, String.valueOf(value));
    }

    /**
     * Removes a property.
     */
    public void removeProperty(String key) {
        if (key != null) {
            properties.remove(key);
            runtimeCache.remove(key);
        }
    }

    /**
     * Checks if a property exists.
     */
    public boolean hasProperty(String key) {
        return properties.containsKey(key);
    }

    /**
     * Saves the configuration to file.
     */
    public synchronized void saveConfiguration() {
        try {
            File configDir = configFile.getParentFile();
            if (!configDir.exists()) {
                if (!configDir.mkdirs()) {
                    System.err.println("Failed to create configuration directory: " + configDir.getAbsolutePath());
                    return;
                }
            }

            try (FileOutputStream fos = new FileOutputStream(configFile)) {
                properties.store(fos, "Java Security Analyzer Configuration");
            }

        } catch (IOException e) {
            System.err.println("Failed to save configuration: " + e.getMessage());
        }
    }

    /**
     * Reloads configuration from file.
     */
    public synchronized void reloadConfiguration() {
        properties.clear();
        runtimeCache.clear();
        loadConfiguration();
        setDefaultValues();
    }

    /**
     * Gets all property keys.
     */
    public java.util.Set<String> getPropertyKeys() {
        return properties.stringPropertyNames();
    }

    /**
     * Gets the configuration file path.
     */
    public String getConfigFilePath() {
        return configFile.getAbsolutePath();
    }

    /**
     * Caches a runtime value that won't be persisted.
     */
    public void setRuntimeValue(String key, Object value) {
        if (key != null) {
            if (value != null) {
                runtimeCache.put(key, value);
            } else {
                runtimeCache.remove(key);
            }
        }
    }

    /**
     * Gets a cached runtime value.
     */
    @SuppressWarnings("unchecked")
    public <T> T getRuntimeValue(String key, Class<T> type) {
        if (key != null) {
            Object value = runtimeCache.get(key);
            if (value != null && type.isInstance(value)) {
                return (T) value;
            }
        }
        return null;
    }

    /**
     * Gets a cached runtime value with a default.
     */
    @SuppressWarnings("unchecked")
    public <T> T getRuntimeValue(String key, Class<T> type, T defaultValue) {
        T value = getRuntimeValue(key, type);
        return value != null ? value : defaultValue;
    }

    /**
     * Clears all runtime cached values.
     */
    public void clearRuntimeCache() {
        runtimeCache.clear();
    }

    /**
     * Removes a runtime cached value.
     */
    public void removeRuntimeValue(String key) {
        if (key != null) {
            runtimeCache.remove(key);
        }
    }

    /**
     * Exports configuration to a string.
     */
    public String exportConfiguration() {
        StringWriter writer = new StringWriter();
        try {
            properties.store(writer, "Exported Java Security Analyzer Configuration");
            return writer.toString();
        } catch (IOException e) {
            System.err.println("Failed to export configuration: " + e.getMessage());
            return "";
        }
    }

    /**
     * Imports configuration from a string.
     */
    public boolean importConfiguration(String configData) {
        try {
            Properties newProperties = new Properties();
            StringReader reader = new StringReader(configData);
            newProperties.load(reader);

            properties.clear();
            properties.putAll(newProperties);
            runtimeCache.clear();

            return true;
        } catch (IOException e) {
            System.err.println("Failed to import configuration: " + e.getMessage());
            return false;
        }
    }

    /**
     * Resets configuration to defaults.
     */
    public synchronized void resetToDefaults() {
        properties.clear();
        runtimeCache.clear();
        setDefaultValues();
        saveConfiguration();
    }

    /**
     * Gets a summary of current configuration.
     */
    @Override
    public String toString() {
        return String.format("ConfigManager{file='%s', properties=%d, runtimeCache=%d}",
                configFile.getAbsolutePath(), properties.size(), runtimeCache.size());
    }
}