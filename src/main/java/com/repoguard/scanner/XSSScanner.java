package com.repoguard.scanner;

import com.repoguard.model.Severity;
import com.repoguard.model.Vulnerability;
import org.springframework.stereotype.Component;

import java.io.File;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.List;

@Component
public class XSSScanner {

    public List<Vulnerability> scan(List<File> javaFiles) {

        List<Vulnerability> vulnerabilities = new ArrayList<>();

        for (File file : javaFiles) {

            try {
                List<String> lines = Files.readAllLines(file.toPath());
                int lineNumber = 1;

                for (String line : lines) {

                    // Direct output of user input without escaping
                    if (line.contains("response.getWriter().print") || line.contains("out.println")) {
                        vulnerabilities.add(new Vulnerability(
                                "XSS",
                                Severity.HIGH,
                                file.getName(),
                                lineNumber,
                                "Possible XSS: User input written directly to HTTP response.",
                                "Escape user input using OWASP Java Encoder or HtmlUtils.htmlEscape()."
                        ));
                    }

                    // HTML building with string concatenation
                    if (line.contains("<") && line.contains("+")) {
                        vulnerabilities.add(new Vulnerability(
                                "XSS",
                                Severity.MEDIUM,
                                file.getName(),
                                lineNumber,
                                "Possible XSS: HTML built via string concatenation with user input.",
                                "Use a templating engine (Thymeleaf, FreeMarker) or escape input before embedding in HTML."
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
