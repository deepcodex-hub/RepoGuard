package com.repoguard;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.repoguard.model.ScanResult;
import com.repoguard.model.Vulnerability;
import com.repoguard.service.FileService;
import com.repoguard.service.NodeScaScanner;
import com.repoguard.service.SASTService;
import com.repoguard.service.SCAScanner;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.stereotype.Component;

import java.io.File;
import java.util.ArrayList;
import java.util.List;
import java.util.Arrays;

@Component
public class CliRunner implements CommandLineRunner {

    @Autowired
    private FileService fileService;

    @Autowired
    private SASTService sastService;

    @Autowired
    private SCAScanner scaScanner;

    @Autowired
    private NodeScaScanner nodeScaScanner;

    @Override
    public void run(String... args) throws Exception {
        String cliRepoPath = null;
        for (String arg : args) {
            if (arg.startsWith("--cli.repoPath=")) {
                cliRepoPath = arg.substring("--cli.repoPath=".length());
            }
        }

        if (cliRepoPath != null) {
            System.out.println("Starting CLI Scan for: " + cliRepoPath);
            
            List<File> javaFiles = fileService.getJavaFiles(cliRepoPath);
            File pomFile = fileService.getPomFile(cliRepoPath);
            File packageJsonFile = fileService.getPackageJsonFile(cliRepoPath);

            List<Vulnerability> vulnerabilities = new ArrayList<>();
            vulnerabilities.addAll(sastService.runSAST(javaFiles));
            vulnerabilities.addAll(scaScanner.scan(pomFile));
            if (packageJsonFile != null) {
                vulnerabilities.addAll(nodeScaScanner.scan(packageJsonFile));
            }

            ScanResult result = new ScanResult("SCAN COMPLETED", vulnerabilities);

            ObjectMapper mapper = new ObjectMapper();
            mapper.enable(SerializationFeature.INDENT_OUTPUT);
            System.out.println("============== REPOGUARD CLI RESULT ==============");
            System.out.println(mapper.writeValueAsString(result));
            System.out.println("==================================================");
            
            // Exit so the container stops after a CLI run
            System.exit(0);
        }
    }
}
