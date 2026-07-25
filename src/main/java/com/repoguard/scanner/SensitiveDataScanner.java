package com.repoguard.scanner;

import com.repoguard.model.Severity;
import com.repoguard.model.Vulnerability;
import org.springframework.stereotype.Component;

import java.io.File;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.List;

@Component
public class SensitiveDataScanner {

    public List<Vulnerability> scan(List<File> javaFiles) {

        List<Vulnerability> vulnerabilities = new ArrayList<>();

        for (File file : javaFiles) {

            try {
                List<String> lines = Files.readAllLines(file.toPath());
                int lineNumber = 1;

                for (String line : lines) {

                    String lower = line.toLowerCase();

                    // Hardcoded passwords
                    if (lower.contains("password") && line.contains("=")) {
                        vulnerabilities.add(new Vulnerability(
                                "HARDCODED_SECRET",
                                Severity.HIGH,
                                file.getName(),
                                lineNumber,
                                "Hardcoded password detected in source code.",
                                "Do not hardcode passwords. Use environment variables or a secrets manager (AWS Secrets Manager, HashiCorp Vault)."
                        ));
                    }

                    // Hardcoded API keys
                    if (lower.contains("apikey") || lower.contains("api_key")) {
                        vulnerabilities.add(new Vulnerability(
                                "HARDCODED_SECRET",
                                Severity.HIGH,
                                file.getName(),
                                lineNumber,
                                "Possible API key exposed in source code.",
                                "Store API keys in environment variables or a secrets manager. Never commit secrets to source control."
                        ));
                    }

                    // Hardcoded tokens
                    if (lower.contains("token") && line.contains("=")) {
                        vulnerabilities.add(new Vulnerability(
                                "HARDCODED_SECRET",
                                Severity.HIGH,
                                file.getName(),
                                lineNumber,
                                "Possible token exposed in source code.",
                                "Store tokens in environment variables or a secrets manager. Never commit secrets to source control."
                        ));
                    }

                    lineNumber++;
                }

            } catch (Exception e) {
                System.out.println("Error reading file: " + file.getName());
            }
        }

        return vulnerabilities;
    }
}
