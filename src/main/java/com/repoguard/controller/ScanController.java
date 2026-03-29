package com.repoguard.controller;

import com.repoguard.model.ScanResult;
import com.repoguard.service.ScanOrchestrator;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/scan")
public class ScanController {

    @Autowired
    private ScanOrchestrator scanOrchestrator;

    @PostMapping
    public ResponseEntity<ScanResult> scanRepository(@RequestParam String repoUrl) {
        ScanResult result = scanOrchestrator.scan(repoUrl);
        return ResponseEntity.ok(result);
    }
}
