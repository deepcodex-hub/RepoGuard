package com.repoguard.scanner;

import com.repoguard.model.Severity;
import com.repoguard.model.Vulnerability;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class XSSScannerTest {

    private final XSSScanner scanner = new XSSScanner();

    @TempDir
    Path tempDir;

    @Test
    void shouldDetectDirectResponseWrite() throws Exception {
        Path javaFile = tempDir.resolve("VulnerableController.java");
        Files.writeString(javaFile,
                "public class VulnerableController {\n" +
                "    public void render(HttpServletResponse response, String input) throws Exception {\n" +
                "        response.getWriter().print(input);\n" + // line 3
                "    }\n" +
                "}\n"
        );

        List<Vulnerability> results = scanner.scan(List.of(javaFile.toFile()));

        assertFalse(results.isEmpty());
        assertEquals("XSS", results.get(0).getType());
        assertEquals(Severity.HIGH, results.get(0).getSeverity());
    }

    @Test
    void shouldDetectHTMLConcatenation() throws Exception {
        Path javaFile = tempDir.resolve("HtmlBuilder.java");
        Files.writeString(javaFile,
                "public class HtmlBuilder {\n" +
                "    public String build(String name) {\n" +
                "        return \"<div>\" + name + \"</div>\";\n" + // line 3
                "    }\n" +
                "}\n"
        );

        List<Vulnerability> results = scanner.scan(List.of(javaFile.toFile()));

        assertFalse(results.isEmpty());
        assertEquals("XSS", results.get(0).getType());
        assertEquals(Severity.MEDIUM, results.get(0).getSeverity());
    }

    @Test
    void shouldReturnNoIssuesForSafeCode() throws Exception {
        Path javaFile = tempDir.resolve("SafeController.java");
        Files.writeString(javaFile,
                "public class SafeController {\n" +
                "    public String greet() {\n" +
                "        return \"Hello World\";\n" +
                "    }\n" +
                "}\n"
        );

        List<Vulnerability> results = scanner.scan(List.of(javaFile.toFile()));

        assertTrue(results.isEmpty());
    }
}
