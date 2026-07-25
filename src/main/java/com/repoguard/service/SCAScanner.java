package com.repoguard.service;

import com.repoguard.model.Dependency;
import com.repoguard.model.Severity;
import com.repoguard.model.Vulnerability;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.io.File;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Service
public class SCAScanner {

    @Autowired
    private CacheService cacheService;

    @Autowired
    private NVDService nvdService;

    public List<Vulnerability> scan(File pomFile) {

        List<Vulnerability> vulnerabilities = new ArrayList<>();

        if (pomFile == null) {
            vulnerabilities.add(new Vulnerability(
                    "MISSING_POM",
                    Severity.LOW,
                    "pom.xml",
                    0,
                    "No pom.xml found. Dependency scan skipped.",
                    "Ensure a pom.xml file exists at the root of your Java project."
            ));
            return vulnerabilities;
        }

        List<Dependency> dependencies = extractDependencies(pomFile);

        for (Dependency dep : dependencies) {

            String key = dep.getArtifactId() + ":" + dep.getVersion();

            String nvdResponse;

            if (cacheService.contains(key)) {
                // Cached result
                nvdResponse = cacheService.get(key);
            } else {
                // Call NVD
                String query = dep.getArtifactId() + " " + dep.getVersion();
                nvdResponse = nvdService.fetchVulnerabilities(query);
                cacheService.put(key, nvdResponse);
            }

            // Assess severity based on known risky libraries
            Severity severity = assessSeverity(dep.getArtifactId(), dep.getVersion());

            vulnerabilities.add(new Vulnerability(
                    "VULNERABLE_DEPENDENCY",
                    severity,
                    "pom.xml",
                    0,
                    "Dependency " + key + " may have known CVEs.",
                    "Check https://nvd.nist.gov for CVEs and upgrade to a patched version."
            ));
        }

        return vulnerabilities;
    }

    /**
     * Simple severity heuristic based on known risky libraries.
     * In a production tool this would parse the actual CVE CVSS score from nvdResponse.
     */
    private Severity assessSeverity(String artifactId, String version) {
        String id = artifactId.toLowerCase();

        // Log4Shell — CRITICAL
        if (id.contains("log4j") && (version.startsWith("1.") || version.startsWith("2.0") || version.startsWith("2.1"))) {
            return Severity.CRITICAL;
        }
        // Old Spring versions with known RCEs
        if (id.contains("spring") && version.startsWith("5.")) {
            return Severity.HIGH;
        }

        return Severity.MEDIUM;
    }

    // 🔍 Extract dependencies from pom.xml
    private List<Dependency> extractDependencies(File pomFile) {

        List<Dependency> dependencies = new ArrayList<>();
        Map<String, String> properties = new HashMap<>();

        try {
            List<String> lines = Files.readAllLines(pomFile.toPath());

            // Pass 1: Extract properties
            boolean inProperties = false;
            for (String line : lines) {
                line = line.trim();
                if (line.startsWith("<properties>")) inProperties = true;
                if (line.startsWith("</properties>")) inProperties = false;

                if (inProperties && line.contains(">") && line.contains("</")) {
                    String key = line.substring(line.indexOf("<") + 1, line.indexOf(">"));
                    String value = line.substring(line.indexOf(">") + 1, line.indexOf("</"));
                    properties.put(key, value);
                }
            }

            // Pass 2: Extract dependencies
            String artifactId = null;
            String version = null;

            for (String line : lines) {

                line = line.trim();

                if (line.startsWith("<artifactId>")) {
                    artifactId = line.replace("<artifactId>", "").replace("</artifactId>", "");
                }

                if (line.startsWith("<version>")) {
                    version = line.replace("<version>", "").replace("</version>", "");

                    // Resolve property placeholders like ${spring.version}
                    if (version.startsWith("${") && version.endsWith("}")) {
                        String propKey = version.substring(2, version.length() - 1);
                        version = properties.getOrDefault(propKey, version);
                    }
                }

                if (artifactId != null && version != null) {
                    dependencies.add(new Dependency(artifactId, version));
                    artifactId = null;
                    version = null;
                }
            }

        } catch (Exception e) {
            System.out.println("Error reading pom.xml: " + e.getMessage());
        }

        return dependencies;
    }
}
