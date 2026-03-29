package com.repoguard.service;

import org.springframework.stereotype.Service;

import java.io.*;
import java.net.URI;
import java.net.URL;
import java.nio.file.*;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

@Service
public class GithubService {

    private static final String TEMP_DIR = "temp-repos/";

    public String cloneRepository(String repoUrl) {

        try {
            File tempDir = new File(TEMP_DIR);

            // Clean up repoUrl (trailing slash)
            if (repoUrl.endsWith("/")) {
                repoUrl = repoUrl.substring(0, repoUrl.length() - 1);
            }

            // Extract repo name and strip .git
            String repoName = repoUrl.substring(repoUrl.lastIndexOf("/") + 1);
            if (repoName.endsWith(".git")) {
                repoName = repoName.substring(0, repoName.length() - 4);
            }

            // 🔥 STEP 1: Clean old repos (VERY IMPORTANT)
            if (tempDir.exists()) {
                deleteDirectory(tempDir);
            }
            tempDir.mkdirs();

            // 🔥 STEP 2: Try main and master branch
            String baseZipUrl = repoUrl.replace(".git", "");
            String zipUrlMain = baseZipUrl + "/archive/refs/heads/main.zip";
            String zipUrlMaster = baseZipUrl + "/archive/refs/heads/master.zip";

            InputStream in;

            try {
                in = URI.create(zipUrlMain).toURL().openStream();
            } catch (Exception e) {
                in = URI.create(zipUrlMaster).toURL().openStream();
            }

            ZipInputStream zis = new ZipInputStream(in);
            ZipEntry entry;

            // 🔥 STEP 3: Extract zip
            while ((entry = zis.getNextEntry()) != null) {

                File file = new File(TEMP_DIR, entry.getName());

                if (entry.isDirectory()) {
                    file.mkdirs();
                } else {
                    new File(file.getParent()).mkdirs();

                    FileOutputStream fos = new FileOutputStream(file);

                    byte[] buffer = new byte[1024];
                    int len;

                    while ((len = zis.read(buffer)) > 0) {
                        fos.write(buffer, 0, len);
                    }

                    fos.close();
                }
            }

            zis.close();

            // 🔥 STEP 4: Return correct extracted repo folder
            File[] files = tempDir.listFiles();

            if (files != null) {
                for (File f : files) {
                    // Match repo name exactly or check if file starts with it
                    // GitHub ZIP folders are typically 'repo-name-main' or 'repo-name-master'
                    if (f.getName().equalsIgnoreCase(repoName) || f.getName().startsWith(repoName + "-")) {
                        return f.getAbsolutePath();
                    }
                }
            }

            throw new RuntimeException("Repo extraction failed for: " + repoName);

        } catch (Exception e) {
            throw new RuntimeException("Error downloading repo: " + e.getMessage());
        }
    }

    // Utility method to delete folder
    private void deleteDirectory(File file) {
        if (file.isDirectory()) {
            File[] files = file.listFiles();
            if (files != null) {
                for (File sub : files) {
                    deleteDirectory(sub);
                }
            }
        }
        file.delete();
    }
}