package com.securityanalyzer.service;

import com.securityanalyzer.exception.FileOperationException;

import java.io.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;

/**
 * Service class for file operations and management.
 * Handles file I/O, validation, and management tasks.
 */
public class FileService {

    /**
     * Validates if a file path is valid and accessible.
     *
     * @param filePath The file path to validate
     * @return True if file is valid and accessible
     */
    public boolean validateFilePath(String filePath) {
        if (filePath == null || filePath.trim().isEmpty()) {
            return false;
        }

        try {
            Path path = Paths.get(filePath);
            return Files.exists(path) && Files.isRegularFile(path) && Files.isReadable(path);
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * Gets the file name from a file path.
     *
     * @param filePath The file path
     * @return The file name
     */
    public String getFileName(String filePath) {
        if (filePath == null) {
            return "";
        }

        Path path = Paths.get(filePath);
        return path.getFileName().toString();
    }

    /**
     * Gets the file extension from a file path.
     *
     * @param filePath The file path
     * @return The file extension (without dot)
     */
    public String getFileExtension(String filePath) {
        if (filePath == null) {
            return "";
        }

        String fileName = getFileName(filePath);
        int lastDotIndex = fileName.lastIndexOf('.');
        if (lastDotIndex > 0 && lastDotIndex < fileName.length() - 1) {
            return fileName.substring(lastDotIndex + 1);
        }
        return "";
    }

    /**
     * Checks if a file has a specific extension.
     *
     * @param filePath The file path
     * @param extension The extension to check (without dot)
     * @return True if file has the specified extension
     */
    public boolean hasExtension(String filePath, String extension) {
        return getFileExtension(filePath).equalsIgnoreCase(extension);
    }

    /**
     * Gets the file size in bytes.
     *
     * @param filePath The file path
     * @return File size in bytes
     * @throws FileOperationException if file cannot be accessed
     */
    public long getFileSize(String filePath) throws FileOperationException {
        try {
            Path path = Paths.get(filePath);
            if (!Files.exists(path)) {
                throw new FileOperationException("File does not exist: " + filePath);
            }
            return Files.size(path);
        } catch (IOException e) {
            throw new FileOperationException("Failed to get file size: " + e.getMessage(), e);
        }
    }

    /**
     * Formats file size to human-readable format.
     *
     * @param bytes Size in bytes
     * @return Formatted size string
     */
    public String formatFileSize(long bytes) {
        if (bytes < 1024) {
            return bytes + " B";
        } else if (bytes < 1024 * 1024) {
            return String.format("%.1f KB", bytes / 1024.0);
        } else if (bytes < 1024 * 1024 * 1024) {
            return String.format("%.1f MB", bytes / (1024.0 * 1024.0));
        } else {
            return String.format("%.1f GB", bytes / (1024.0 * 1024.0 * 1024.0));
        }
    }

    /**
     * Reads all text content from a file.
     *
     * @param filePath The file path
     * @return File content as string
     * @throws FileOperationException if file cannot be read
     */
    public String readFileContent(String filePath) throws FileOperationException {
        try {
            Path path = Paths.get(filePath);
            return Files.readString(path);
        } catch (IOException e) {
            throw new FileOperationException("Failed to read file: " + e.getMessage(), e);
        }
    }

    /**
     * Writes text content to a file.
     *
     * @param filePath The file path
     * @param content The content to write
     * @throws FileOperationException if file cannot be written
     */
    public void writeFileContent(String filePath, String content) throws FileOperationException {
        try {
            Path path = Paths.get(filePath);
            Files.writeString(path, content);
        } catch (IOException e) {
            throw new FileOperationException("Failed to write file: " + e.getMessage(), e);
        }
    }

    /**
     * Creates a backup of a file.
     *
     * @param originalFilePath The original file path
     * @return Path to the backup file
     * @throws FileOperationException if backup cannot be created
     */
    public String createBackup(String originalFilePath) throws FileOperationException {
        try {
            Path originalPath = Paths.get(originalFilePath);
            String backupPath = originalFilePath + ".backup." + System.currentTimeMillis();
            Path backupFile = Paths.get(backupPath);

            Files.copy(originalPath, backupFile);
            return backupPath;
        } catch (IOException e) {
            throw new FileOperationException("Failed to create backup: " + e.getMessage(), e);
        }
    }

    /**
     * Deletes a file safely.
     *
     * @param filePath The file path to delete
     * @return True if file was deleted successfully
     */
    public boolean deleteFile(String filePath) {
        try {
            Path path = Paths.get(filePath);
            return Files.deleteIfExists(path);
        } catch (IOException e) {
            return false;
        }
    }

    /**
     * Checks if a directory exists, creates it if it doesn't.
     *
     * @param directoryPath The directory path
     * @return True if directory exists or was created
     * @throws FileOperationException if directory cannot be created
     */
    public boolean ensureDirectoryExists(String directoryPath) throws FileOperationException {
        try {
            Path path = Paths.get(directoryPath);
            if (!Files.exists(path)) {
                Files.createDirectories(path);
            }
            return Files.exists(path) && Files.isDirectory(path);
        } catch (IOException e) {
            throw new FileOperationException("Failed to create directory: " + e.getMessage(), e);
        }
    }

    /**
     * Lists all files in a directory with specific extension.
     *
     * @param directoryPath The directory path
     * @param extension The file extension to filter (without dot)
     * @return List of file paths
     */
    public List<String> listFilesByExtension(String directoryPath, String extension) {
        List<String> files = new ArrayList<>();
        try {
            Path directory = Paths.get(directoryPath);
            if (Files.exists(directory) && Files.isDirectory(directory)) {
                Files.list(directory)
                     .filter(path -> Files.isRegularFile(path))
                     .filter(path -> getFileExtension(path.toString()).equalsIgnoreCase(extension))
                     .map(Path::toString)
                     .forEach(files::add);
            }
        } catch (IOException e) {
            // Return empty list on error
        }
        return files;
    }

    /**
     * Validates if a file is likely to be a text file.
     *
     * @param filePath The file path
     * @return True if file appears to be text
     */
    public boolean isTextFile(String filePath) {
        String extension = getFileExtension(filePath);
        String[] textExtensions = {"txt", "json", "xml", "csv", "log", "properties", "yaml", "yml", "md"};

        for (String textExt : textExtensions) {
            if (extension.equalsIgnoreCase(textExt)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Gets a temporary file path.
     *
     * @param prefix File name prefix
     * @param extension File extension (without dot)
     * @return Temporary file path
     */
    public String getTempFilePath(String prefix, String extension) {
        String tempDir = System.getProperty("java.io.tmpdir");
        String fileName = prefix + "_" + System.currentTimeMillis() + "." + extension;
        return Paths.get(tempDir, fileName).toString();
    }

    /**
     * Validates if a file path is safe for writing.
     *
     * @param filePath The file path to validate
     * @return True if path is safe
     */
    public boolean isSafeFilePath(String filePath) {
        if (filePath == null || filePath.trim().isEmpty()) {
            return false;
        }

        // Check for path traversal attempts
        if (filePath.contains("..") || filePath.contains("~")) {
            return false;
        }

        try {
            Path path = Paths.get(filePath);
            Path normalizedPath = path.normalize();

            // Check if path is within allowed directories
            String allowedPrefix = System.getProperty("user.home");
            return normalizedPath.startsWith(allowedPrefix) ||
                   normalizedPath.startsWith(System.getProperty("java.io.tmpdir"));
        } catch (Exception e) {
            return false;
        }
    }
}