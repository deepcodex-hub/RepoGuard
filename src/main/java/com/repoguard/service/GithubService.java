package com.repoguard.service;

import org.springframework.stereotype.Service;

import java.io.File;
import java.io.IOException;

@Service
public class GithubService {

    private static final String TEMP_DIR = "temp-repos/";

    public String cloneRepository(String repoUrl) {

        try {
            // Create temp directory if not exists
            File tempDir = new File(TEMP_DIR);
            if (!tempDir.exists()) {
                tempDir.mkdirs();
            }

            // Generate folder name
            String repoName = repoUrl.substring(repoUrl.lastIndexOf("/") + 1);
            String clonePath = TEMP_DIR + repoName;

            File repoFolder = new File(clonePath);

            // If already exists, delete it
            if (repoFolder.exists()) {
                deleteDirectory(repoFolder);
            }

            // Run git clone command
            ProcessBuilder builder = new ProcessBuilder(
                    "git", "clone", repoUrl, clonePath
            );

            builder.inheritIO(); // show logs in console

            Process process = builder.start();
            int exitCode = process.waitFor();

            if (exitCode == 0) {
                return clonePath;
            } else {
                throw new RuntimeException("Failed to clone repository");
            }

        } catch (Exception e) {
            throw new RuntimeException("Error cloning repo: " + e.getMessage());
        }
    }

    // Utility method to delete folder
    private void deleteDirectory(File file) {
        if (file.isDirectory()) {
            for (File sub : file.listFiles()) {
                deleteDirectory(sub);
            }
        }
        file.delete();
    }
}
