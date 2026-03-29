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
            File tempDir = new File(TEMP_DIR);

            // 🔥 STEP 1: Clean old repos (VERY IMPORTANT)
            if (tempDir.exists()) {
                deleteDirectory(tempDir);
            }
            tempDir.mkdirs();

            // Extract repo name
            String repoName = repoUrl.substring(repoUrl.lastIndexOf("/") + 1);

            // 🔥 STEP 2: Try main and master branch
            String zipUrlMain = repoUrl + "/archive/refs/heads/main.zip";
            String zipUrlMaster = repoUrl + "/archive/refs/heads/master.zip";

            InputStream in;

            try {
                in = new URL(zipUrlMain).openStream();
            } catch (Exception e) {
                in = new URL(zipUrlMaster).openStream();
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
                    if (f.getName().startsWith(repoName)) {
                        return f.getAbsolutePath(); // ✅ correct repo folder
                    }
                }
            }

            throw new RuntimeException("Repo extraction failed");

        } catch (Exception e) {
            throw new RuntimeException("Error downloading repo: " + e.getMessage());
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