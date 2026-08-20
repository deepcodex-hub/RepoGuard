package com.repoguard.service;

import org.springframework.stereotype.Service;

import java.io.File;
import java.util.ArrayList;
import java.util.List;

@Service
public class FileService {

    public List<File> getJavaFiles(String repoPath) {
        List<File> javaFiles = new ArrayList<>();
        File root = new File(repoPath);

        findJavaFiles(root, javaFiles);

        return javaFiles;
    }

    public File getPomFile(String repoPath) {
        File root = new File(repoPath);
        return findFileByName(root, "pom.xml");
    }

    public File getPackageJsonFile(String repoPath) {
        File root = new File(repoPath);
        return findFileByName(root, "package.json");
    }

    // 🔍 Recursively find .java files
    private void findJavaFiles(File dir, List<File> javaFiles) {

        if (dir == null || !dir.exists()) return;

        for (File file : dir.listFiles()) {

            // Ignore unnecessary folders
            if (file.isDirectory()) {
                String name = file.getName();

                if (name.equals(".git") || name.equals("target") || name.equals("node_modules")) {
                    continue;
                }

                findJavaFiles(file, javaFiles);

            } else {
                if (file.getName().endsWith(".java")) {
                    javaFiles.add(file);
                }
            }
        }
    }

    // 🔍 Generic method to find a specific file by name
    private File findFileByName(File dir, String fileName) {
        if (dir == null || !dir.exists() || dir.listFiles() == null) return null;

        for (File file : dir.listFiles()) {
            if (file.isDirectory()) {
                // Ignore .git, target, node_modules
                String name = file.getName();
                if (name.equals(".git") || name.equals("target") || name.equals("node_modules")) continue;
                
                File result = findFileByName(file, fileName);
                if (result != null) return result;
            } else {
                if (file.getName().equals(fileName)) {
                    return file;
                }
            }
        }
        return null;
    }
}

