package com.repoguard.model;

import java.util.List;

public class ScanResult {

    private String status;
    private int totalIssues;
    private List<String> issues;

    public ScanResult() {}

    public ScanResult(String status, List<String> issues) {
        this.status = status;
        this.issues = issues;
        this.totalIssues = issues.size();
    }

    public String getStatus() { return status; }
    public void setStatus(String status) { this.status = status; }

    public int getTotalIssues() { return totalIssues; }

    public List<String> getIssues() { return issues; }
    public void setIssues(List<String> issues) {
        this.issues = issues;
        this.totalIssues = issues.size();
    }
}
