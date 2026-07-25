package com.repoguard.model;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class ScanResult {

    private String status;
    private int totalIssues;
    private Map<String, Long> severitySummary;
    private List<Vulnerability> issues;

    public ScanResult() {}

    public ScanResult(String status, List<Vulnerability> issues) {
        this.status = status;
        this.issues = issues;
        this.totalIssues = issues.size();
        this.severitySummary = buildSeveritySummary(issues);
    }

    private Map<String, Long> buildSeveritySummary(List<Vulnerability> issues) {
        Map<String, Long> summary = new HashMap<>();
        summary.put("CRITICAL", issues.stream().filter(v -> v.getSeverity() == Severity.CRITICAL).count());
        summary.put("HIGH",     issues.stream().filter(v -> v.getSeverity() == Severity.HIGH).count());
        summary.put("MEDIUM",   issues.stream().filter(v -> v.getSeverity() == Severity.MEDIUM).count());
        summary.put("LOW",      issues.stream().filter(v -> v.getSeverity() == Severity.LOW).count());
        return summary;
    }

    public String getStatus() { return status; }
    public void setStatus(String status) { this.status = status; }

    public int getTotalIssues() { return totalIssues; }

    public Map<String, Long> getSeveritySummary() { return severitySummary; }

    public List<Vulnerability> getIssues() { return issues; }
    public void setIssues(List<Vulnerability> issues) {
        this.issues = issues;
        this.totalIssues = issues.size();
        this.severitySummary = buildSeveritySummary(issues);
    }
}
