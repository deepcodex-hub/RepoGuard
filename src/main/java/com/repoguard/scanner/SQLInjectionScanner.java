package com.repoguard.scanner;

import org.springframework.stereotype.Component;

import java.io.File;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.List;

@Component
public class SQLInjectionScanner {

    public List<String> scan(List<File> javaFiles) {

        List<String> issues = new ArrayList<>();

        for (File file : javaFiles) {

            try {
                List<String> lines = Files.readAllLines(file.toPath());

                int lineNumber = 1;

                for (String line : lines) {

                    // Basic SQL injection pattern
                    if (line.contains("SELECT") && line.contains("+")) {
                        issues.add("Possible SQL Injection in file: "
                                + file.getName() + " at line " + lineNumber);
                    }

                    if (line.contains("INSERT") && line.contains("+")) {
                        issues.add("Possible SQL Injection in file: "
                                + file.getName() + " at line " + lineNumber);
                    }

                    if (line.contains("Statement") && line.contains("execute")) {
                        issues.add("Unsafe SQL execution in file: "
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
