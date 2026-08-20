package com.repoguard.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.repoguard.model.Severity;
import com.repoguard.model.Vulnerability;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.io.File;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.Iterator;
import java.util.Map;

@Service
public class NodeScaScanner {

    @Autowired
    private CacheService cacheService;

    @Autowired
    private NVDService nvdService;

    private static final ObjectMapper objectMapper = new ObjectMapper();

    public List<Vulnerability> scan(File packageJsonFile) {
        List<Vulnerability> vulnerabilities = new ArrayList<>();

        if (packageJsonFile == null) {
            return vulnerabilities; // Valid state, maybe it's not a Node project
        }

        try {
            String content = Files.readString(packageJsonFile.toPath());
            JsonNode root = objectMapper.readTree(content);
            
            checkDependencies(root.path("dependencies"), vulnerabilities);
            checkDependencies(root.path("devDependencies"), vulnerabilities);

        } catch (Exception e) {
            System.out.println("Error reading package.json: " + e.getMessage());
        }

        return vulnerabilities;
    }

    private void checkDependencies(JsonNode depsNode, List<Vulnerability> vulnerabilities) {
        if (depsNode.isMissingNode() || !depsNode.isObject()) return;

        Iterator<Map.Entry<String, JsonNode>> fields = depsNode.fields();
        while (fields.hasNext()) {
            Map.Entry<String, JsonNode> field = fields.next();
            String name = field.getKey();
            String version = field.getValue().asText().replaceAll("[^0-9.]", ""); // clean ^ and ~
            
            if (version.isEmpty()) continue;

            String key = name + ":" + version;
            String nvdResponse;

            if (cacheService.contains(key)) {
                nvdResponse = cacheService.get(key);
            } else {
                String query = name + " " + version;
                nvdResponse = nvdService.fetchVulnerabilities(query);
                cacheService.put(key, nvdResponse);
            }

            NvdResult result = parseNvdResponse(nvdResponse);
            if (!result.cveIds.isEmpty()) {
                Severity sev = assessSeverity(result);
                String description = "Node Dependency " + key + " matched NVD CVEs: " + result.cveIds;
                if (result.maxCvssScore > 0) {
                    description += " (Max CVSS: " + result.maxCvssScore + ")";
                }

                vulnerabilities.add(new Vulnerability(
                        "VULNERABLE_DEPENDENCY",
                        sev,
                        "package.json",
                        0,
                        description,
                        "Upgrade " + name + " via npm install or yarn."
                ));
            }
        }
    }

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

                    JsonNode metrics = cve.path("metrics");
                    JsonNode cvssV31 = metrics.path("cvssMetricV31");
                    if (cvssV31.isArray() && !cvssV31.isEmpty()) {
                        double score = cvssV31.get(0).path("cvssData").path("baseScore").asDouble(0.0);
                        result.maxCvssScore = Math.max(result.maxCvssScore, score);
                    }
                }
            }
        } catch (Exception e) {}
        return result;
    }

    private Severity assessSeverity(NvdResult result) {
        if (result.maxCvssScore >= 9.0) return Severity.CRITICAL;
        if (result.maxCvssScore >= 7.0) return Severity.HIGH;
        if (result.maxCvssScore >= 4.0) return Severity.MEDIUM;
        return Severity.LOW;
    }

    private static class NvdResult {
        Set<String> cveIds = new HashSet<>();
        double maxCvssScore = 0.0;
    }
}
