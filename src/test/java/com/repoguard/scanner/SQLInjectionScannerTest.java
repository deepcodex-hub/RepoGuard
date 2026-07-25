package com.repoguard.scanner;

import com.repoguard.model.Severity;
import com.repoguard.model.Vulnerability;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class SQLInjectionScannerTest {

    private final SQLInjectionScanner scanner = new SQLInjectionScanner();

    @TempDir
    Path tempDir;

    @Test
    void shouldDetectSQLInjectionViaConcatenation() throws IOException {
        // Arrange
        Path javaFile = tempDir.resolve("VulnerableDao.java");
        Files.writeString(javaFile,
                "public class VulnerableDao {\n" +
                "    public void getUser(String id) {\n" +
                "        String sql = \"SELECT * FROM users WHERE id = \" + id;\n" + // line 3
                "    }\n" +
                "}\n"
        );

        // Act
        List<Vulnerability> results = scanner.scan(List.of(javaFile.toFile()));

        // Assert
        assertFalse(results.isEmpty(), "Should detect SQL injection");
        Vulnerability v = results.get(0);
        assertEquals("SQL_INJECTION", v.getType());
        assertEquals(Severity.CRITICAL, v.getSeverity());
        assertEquals("VulnerableDao.java", v.getFileName());
        assertEquals(3, v.getLineNumber());
        assertNotNull(v.getFix());
    }

    @Test
    void shouldDetectUnsafeStatementExecute() throws IOException {
        // Arrange
        Path javaFile = tempDir.resolve("UnsafeDao.java");
        Files.writeString(javaFile,
                "public class UnsafeDao {\n" +
                "    public void run(java.sql.Statement stmt) throws Exception {\n" +
                "        Statement.execute(query);\n" + // line 3 — contains both 'Statement' and 'execute'
                "    }\n" +
                "}\n"
        );

        // Act
        List<Vulnerability> results = scanner.scan(List.of(javaFile.toFile()));

        // Assert
        assertFalse(results.isEmpty(), "Should detect unsafe Statement.execute");
        assertEquals("SQL_INJECTION", results.get(0).getType());
        assertEquals(Severity.HIGH, results.get(0).getSeverity());
    }

    @Test
    void shouldReturnNoIssuesForCleanCode() throws IOException {
        // Arrange
        Path javaFile = tempDir.resolve("SafeDao.java");
        Files.writeString(javaFile,
                "public class SafeDao {\n" +
                "    public void getUser(String id) {\n" +
                "        PreparedStatement ps = conn.prepareStatement(\"SELECT * FROM users WHERE id = ?\");\n" +
                "        ps.setString(1, id);\n" +
                "    }\n" +
                "}\n"
        );

        // Act
        List<Vulnerability> results = scanner.scan(List.of(javaFile.toFile()));

        // Assert
        assertTrue(results.isEmpty(), "Clean code should produce no findings");
    }
}
