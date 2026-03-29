package com.repoguard.service;

import com.repoguard.scanner.SQLInjectionScanner;
import com.repoguard.scanner.SensitiveDataScanner;
import com.repoguard.scanner.XSSScanner;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.io.File;
import java.util.ArrayList;
import java.util.List;

@Service
public class SASTService {

    @Autowired
    private SQLInjectionScanner sqlInjectionScanner;

    @Autowired
    private XSSScanner xssScanner;

    @Autowired
    private SensitiveDataScanner sensitiveDataScanner;

    public List<String> runSAST(List<File> javaFiles) {

        List<String> issues = new ArrayList<>();

        // SQL Injection
        issues.addAll(sqlInjectionScanner.scan(javaFiles));

        // XSS
        issues.addAll(xssScanner.scan(javaFiles));

        // Sensitive Data
        issues.addAll(sensitiveDataScanner.scan(javaFiles));

        return issues;
    }
}
