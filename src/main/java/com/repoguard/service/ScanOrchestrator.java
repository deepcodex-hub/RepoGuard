package com.repoguard.service;

import com.repoguard.model.ScanResult;
import com.repoguard.model.Vulnerability;
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
    private NodeScaScanner nodeScaScanner;

    public ScanResult scan(String repoUrl) {

        // Step 1: Clone repo
        String repoPath = githubService.cloneRepository(repoUrl);

        // Step 2: Read files
        List<File> javaFiles = fileService.getJavaFiles(repoPath);
        File pomFile = fileService.getPomFile(repoPath);
        File packageJsonFile = fileService.getPackageJsonFile(repoPath);

        List<Vulnerability> vulnerabilities = new ArrayList<>();

        // Step 3: SAST scan
        vulnerabilities.addAll(sastService.runSAST(javaFiles));

        // Step 4: Java SCA scan
        vulnerabilities.addAll(scaScanner.scan(pomFile));

        // Step 5: Node.js SCA scan
        if (packageJsonFile != null) {
            vulnerabilities.addAll(nodeScaScanner.scan(packageJsonFile));
        }

        return new ScanResult("SCAN COMPLETED", vulnerabilities);
    }
}

