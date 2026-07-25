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
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

@Service
public class SCAScanner {

    @Autowired
    private CacheService cacheService;

    @Autowired
    private NVDService nvdService;

    private static final Pattern CVE_PATTERN = Pattern.compile("CVE-\\d{4}-\\d+");

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
                nvdResponse = cacheService.get(key);
            } else {
                String query = dep.getArtifactId() + " " + dep.getVersion();
                nvdResponse = nvdService.fetchVulnerabilities(query);
                cacheService.put(key, nvdResponse);
            }

            // Extract real CVE IDs returned by NVD API response
            Set<String> cveIds = extractCveIds(nvdResponse);

            Severity severity = assessSeverity(dep.getArtifactId(), dep.getVersion(), cveIds);

            String description;
            if (!cveIds.isEmpty()) {
                description = "Dependency " + key + " matched NVD CVEs: " + cveIds;
            } else {
                description = "Dependency " + key + " scanned against NVD database.";
            }

            vulnerabilities.add(new Vulnerability(
                    "VULNERABLE_DEPENDENCY",
                    severity,
                    "pom.xml",
                    0,
                    description,
                    "Upgrade " + dep.getArtifactId() + " to a secure patched version."
            ));
        }

        return vulnerabilities;
    }

    /**
     * Extracts real CVE IDs (e.g. CVE-2021-44228) from NVD JSON response.
     */
    private Set<String> extractCveIds(String nvdResponse) {
        Set<String> cveSet = new HashSet<>();
        if (nvdResponse == null || nvdResponse.isEmpty() || nvdResponse.contains("Error fetching")) {
            return cveSet;
        }

        Matcher matcher = CVE_PATTERN.matcher(nvdResponse);
        while (matcher.find() && cveSet.size() < 5) { // Limit to top 5 distinct CVEs for readable response
            cveSet.add(matcher.group());
        }
        return cveSet;
    }

    /**
     * Assesses severity based on extracted CVEs and known critical libraries.
     */
    private Severity assessSeverity(String artifactId, String version, Set<String> cveIds) {
        String id = artifactId.toLowerCase();

        // If NVD returned active CVEs
        if (!cveIds.isEmpty()) {
            if (id.contains("log4j") || id.contains("spring")) {
                return Severity.CRITICAL;
            }
            return Severity.HIGH;
        }

        // Heuristic fallback for known vulnerable components
        if (id.contains("log4j") && (version.startsWith("1.") || version.startsWith("2.0") || version.startsWith("2.1"))) {
            return Severity.CRITICAL;
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
