package com.repoguard.service;

import org.springframework.stereotype.Service;

import java.io.*;
import java.net.URL;
import java.nio.file.*;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

@Service
public class GithubService {

    private static final String TEMP_DIR = "temp-repos/";

    public String cloneRepository(String repoUrl) {

        try {
            // Create temp directory
            Files.createDirectories(Paths.get(TEMP_DIR));

            // Extract repo name
            String repoName = repoUrl.substring(repoUrl.lastIndexOf("/") + 1);
            String extractPath = TEMP_DIR + repoName;

            File repoFolder = new File(extractPath);

            // Delete if exists
            if (repoFolder.exists()) {
                deleteDirectory(repoFolder);
            }

            // Convert GitHub URL to ZIP URL
            String zipUrl = repoUrl + "/archive/refs/heads/main.zip";

            // Download ZIP
            InputStream in = new URL(zipUrl).openStream();
            ZipInputStream zis = new ZipInputStream(in);

            ZipEntry entry;

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

            return TEMP_DIR;

        } catch (Exception e) {
            throw new RuntimeException("Error downloading repo: " + e.getMessage());
        }
    }

    private void deleteDirectory(File file) {
        if (file.isDirectory()) {
            for (File sub : file.listFiles()) {
                deleteDirectory(sub);
            }
        }
        file.delete();
    }
}