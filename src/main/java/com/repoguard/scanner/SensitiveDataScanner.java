package com.repoguard.scanner;

import org.springframework.stereotype.Component;

import java.io.File;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.List;

@Component
public class SensitiveDataScanner {

    public List<String> scan(List<File> javaFiles) {

        List<String> issues = new ArrayList<>();

        for (File file : javaFiles) {

            try {
                List<String> lines = Files.readAllLines(file.toPath());
                int lineNumber = 1;

                for (String line : lines) {

                    String lowerLine = line.toLowerCase();

                    // Detect hardcoded passwords
                    if (lowerLine.contains("password") && line.contains("=")) {
                        issues.add("Hardcoded password in file: "
                                + file.getName() + " at line " + lineNumber);
                    }

                    // Detect API keys
                    if (lowerLine.contains("apikey") || lowerLine.contains("api_key")) {
                        issues.add("Possible API key exposure in file: "
                                + file.getName() + " at line " + lineNumber);
                    }

                    // Detect tokens
                    if (lowerLine.contains("token") && line.contains("=")) {
                        issues.add("Possible token exposure in file: "
                                + file.getName() + " at line " + lineNumber);
                    }

                    lineNumber++;
                }

            } catch (Exception e) {
                System.out.println("Error reading file: " + file.getName());
            }
        }

        return issues;
    }
}
