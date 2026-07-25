package com.repoguard.scanner;

import com.repoguard.model.Severity;
import com.repoguard.model.Vulnerability;
import org.springframework.stereotype.Component;

import java.io.File;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.List;

@Component
public class SQLInjectionScanner {

    public List<Vulnerability> scan(List<File> javaFiles) {

        List<Vulnerability> vulnerabilities = new ArrayList<>();

        for (File file : javaFiles) {

            try {
                List<String> lines = Files.readAllLines(file.toPath());
                int lineNumber = 1;

                for (String line : lines) {

                    // Direct string concatenation in SQL query
                    if ((line.contains("SELECT") || line.contains("INSERT") || line.contains("UPDATE") || line.contains("DELETE"))
                            && line.contains("+")) {
                        vulnerabilities.add(new Vulnerability(
                                "SQL_INJECTION",
                                Severity.CRITICAL,
                                file.getName(),
                                lineNumber,
                                "Possible SQL Injection via string concatenation in query.",
                                "Use PreparedStatement or parameterized queries."
                        ));
                    }

                    // Raw Statement.execute usage
                    if (line.contains("Statement") && line.contains("execute")) {
                        vulnerabilities.add(new Vulnerability(
                                "SQL_INJECTION",
                                Severity.HIGH,
                                file.getName(),
                                lineNumber,
                                "Unsafe SQL execution using raw Statement.",
                                "Replace with PreparedStatement to prevent injection."
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
