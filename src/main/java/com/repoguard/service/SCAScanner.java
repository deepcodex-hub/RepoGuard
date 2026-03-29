package com.repoguard.service;

import com.repoguard.model.Dependency;
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

    public List<String> scan(File pomFile) {

        List<String> issues = new ArrayList<>();

        if (pomFile == null) {
            issues.add("No pom.xml found");
            return issues;
        }

        List<Dependency> dependencies = extractDependencies(pomFile);

        for (Dependency dep : dependencies) {

            String key = dep.getArtifactId() + ":" + dep.getVersion();

            // Check cache
            if (cacheService.contains(key)) {
                issues.add("Cached CVE found for " + key);
                continue;
            }

            // Call NVD
            String query = dep.getArtifactId() + " " + dep.getVersion();
            String response = nvdService.fetchVulnerabilities(query);

            // Store in cache
            cacheService.put(key, response);

            issues.add("Scanned dependency: " + key);
        }

        return issues;
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
                    artifactId = line.replace("<artifactId>", "")
                                     .replace("</artifactId>", "");
                }

                if (line.startsWith("<version>")) {
                    version = line.replace("<version>", "")
                                  .replace("</version>", "");

                    // Resolve property if version is a placeholder ${version.name}
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
            System.out.println("Error reading pom.xml");
        }

        return dependencies;
    }
}
