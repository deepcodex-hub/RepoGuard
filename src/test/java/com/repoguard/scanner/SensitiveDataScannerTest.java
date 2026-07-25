package com.repoguard.scanner;

import com.repoguard.model.Severity;
import com.repoguard.model.Vulnerability;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class SensitiveDataScannerTest {

    private final SensitiveDataScanner scanner = new SensitiveDataScanner();

    @TempDir
    Path tempDir;

    @Test
    void shouldDetectHardcodedPassword() throws Exception {
        Path javaFile = tempDir.resolve("Config.java");
        Files.writeString(javaFile,
                "public class Config {\n" +
                "    String password = \"mysecret123\";\n" + // line 2
                "}\n"
        );

        List<Vulnerability> results = scanner.scan(List.of(javaFile.toFile()));

        assertFalse(results.isEmpty());
        assertTrue(results.stream().anyMatch(v -> v.getType().equals("HARDCODED_SECRET")));
        assertTrue(results.stream().anyMatch(v -> v.getSeverity() == Severity.HIGH));
    }

    @Test
    void shouldDetectHardcodedAPIKey() throws Exception {
        Path javaFile = tempDir.resolve("AppConfig.java");
        Files.writeString(javaFile,
                "public class AppConfig {\n" +
                "    String apiKey = \"sk-abc123\";\n" + // line 2
                "}\n"
        );

        List<Vulnerability> results = scanner.scan(List.of(javaFile.toFile()));

        assertFalse(results.isEmpty());
        assertEquals("HARDCODED_SECRET", results.get(0).getType());
    }

    @Test
    void shouldDetectHardcodedToken() throws Exception {
        Path javaFile = tempDir.resolve("Security.java");
        Files.writeString(javaFile,
                "public class Security {\n" +
                "    String token = \"Bearer eyJhbGci...\";\n" + // line 2
                "}\n"
        );

        List<Vulnerability> results = scanner.scan(List.of(javaFile.toFile()));

        assertFalse(results.isEmpty());
        assertEquals("HARDCODED_SECRET", results.get(0).getType());
    }

    @Test
    void shouldReturnNoIssuesForSafeConfig() throws Exception {
        Path javaFile = tempDir.resolve("SafeConfig.java");
        Files.writeString(javaFile,
                "public class SafeConfig {\n" +
                "    String dbUrl = System.getenv(\"DB_URL\");\n" +
                "}\n"
        );

        List<Vulnerability> results = scanner.scan(List.of(javaFile.toFile()));

        assertTrue(results.isEmpty());
    }
}
