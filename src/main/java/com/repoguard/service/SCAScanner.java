package com.repoguard.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
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

@Service
public class SCAScanner {

    @Autowired
    private CacheService cacheService;

    @Autowired
    private NVDService nvdService;

    private static final ObjectMapper objectMapper = new ObjectMapper();

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

            // Extract CVSS Data from NVD API JSON
            NvdResult result = parseNvdResponse(nvdResponse);

            Severity severity = assessSeverity(dep.getArtifactId(), dep.getVersion(), result);

            String description;
            if (!result.cveIds.isEmpty()) {
                description = "Dependency " + key + " matched NVD CVEs: " + result.cveIds;
                if (result.maxCvssScore > 0) {
                    description += " (Max CVSS: " + result.maxCvssScore + ")";
                }
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
     * Parses the NVD JSON response to extract CVE IDs and the maximum CVSS base score.
     */
    private NvdResult parseNvdResponse(String nvdResponse) {
        NvdResult result = new NvdResult();
        if (nvdResponse == null || nvdResponse.isEmpty() || nvdResponse.startsWith("Error")) {
            return result;
        }

        try {
            JsonNode root = objectMapper.readTree(nvdResponse);
            JsonNode vulns = root.path("vulnerabilities");

            if (vulns.isArray()) {
                for (JsonNode vulnObj : vulns) {
                    JsonNode cve = vulnObj.path("cve");
                    String cveId = cve.path("id").asText(null);
                    
                    if (cveId != null && result.cveIds.size() < 5) {
                        result.cveIds.add(cveId);
                    }

                    // Attempt to parse CVSS V3.1 or V3.0
                    JsonNode metrics = cve.path("metrics");
                    JsonNode cvssV31 = metrics.path("cvssMetricV31");
                    if (cvssV31.isArray() && !cvssV31.isEmpty()) {
                        double score = cvssV31.get(0).path("cvssData").path("baseScore").asDouble(0.0);
                        result.maxCvssScore = Math.max(result.maxCvssScore, score);
                    }
                }
            }
        } catch (Exception e) {
            // Ignore parse errors, fallback to empty
        }

        return result;
    }

    private Severity assessSeverity(String artifactId, String version, NvdResult result) {
        if (result.maxCvssScore > 0) {
            if (result.maxCvssScore >= 9.0) return Severity.CRITICAL;
            if (result.maxCvssScore >= 7.0) return Severity.HIGH;
            if (result.maxCvssScore >= 4.0) return Severity.MEDIUM;
            return Severity.LOW;
        }

        // Fallback heuristics if parsing fails or no CVSS data
        if (!result.cveIds.isEmpty()) {
            return Severity.HIGH;
        }
        
        String id = artifactId.toLowerCase();
        if (id.contains("log4j") && (version.startsWith("1.") || version.startsWith("2.0") || version.startsWith("2.1"))) {
            return Severity.CRITICAL;
        }
        return Severity.MEDIUM;
    }

    private static class NvdResult {
        Set<String> cveIds = new HashSet<>();
        double maxCvssScore = 0.0;
    }

    // Extract dependencies from pom.xml
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
