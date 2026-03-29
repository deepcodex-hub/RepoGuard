package com.repoguard.scanner;

import org.springframework.stereotype.Component;

import java.io.File;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.List;

@Component
public class XSSScanner {

    public List<String> scan(List<File> javaFiles) {

        List<String> issues = new ArrayList<>();

        for (File file : javaFiles) {

            try {
                List<String> lines = Files.readAllLines(file.toPath());
                int lineNumber = 1;

                for (String line : lines) {

                    // Detect direct output of user input
                    if (line.contains("response.getWriter().print")
                            || line.contains("out.println")) {

                        issues.add("Possible XSS in file: "
                                + file.getName() + " at line " + lineNumber);
                    }

                    // Detect HTML building with +
                    if (line.contains("<") && line.contains("+")) {
                        issues.add("Possible XSS (HTML concatenation) in file: "
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
