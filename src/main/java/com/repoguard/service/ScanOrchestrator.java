package com.repoguard.service;

import com.repoguard.model.ScanResult;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.io.File;
import java.util.ArrayList;
import java.util.List;

@Service
public class ScanOrchestrator {

    @Autowired
    private GithubService githubService;

    @Autowired
    private FileService fileService;

    @Autowired
    private SASTService sastService;

    @Autowired
    private SCAScanner scaScanner;

    @Autowired
    private FixSuggestionService fixSuggestionService;

    public ScanResult scan(String repoUrl) {

        // Step 1: Clone repo
        String repoPath = githubService.cloneRepository(repoUrl);

        // Step 2: Read files
        List<File> javaFiles = fileService.getJavaFiles(repoPath);
        File pomFile = fileService.getPomFile(repoPath);

        List<String> issues = new ArrayList<>();

        // Step 3: SAST
        issues.addAll(sastService.runSAST(javaFiles));

        // Step 4: SCA
        issues.addAll(scaScanner.scan(pomFile));

        // Step 5: Add fix suggestions
        issues = fixSuggestionService.addFixSuggestions(issues);

        return new ScanResult("SCAN COMPLETED", issues);
    }
}
