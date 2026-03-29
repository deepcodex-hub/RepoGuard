package com.repoguard.service;

import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;

@Service
public class FixSuggestionService {

    public List<String> addFixSuggestions(List<String> issues) {

        List<String> enhanced = new ArrayList<>();

        for (String issue : issues) {

            if (issue.toLowerCase().contains("sql injection")) {
                enhanced.add(issue + " → Fix: Use PreparedStatement or parameterized queries.");
            }
            else if (issue.toLowerCase().contains("xss")) {
                enhanced.add(issue + " → Fix: Escape user input before rendering.");
            }
            else if (issue.toLowerCase().contains("password")) {
                enhanced.add(issue + " → Fix: Do not hardcode passwords. Use environment variables.");
            }
            else if (issue.toLowerCase().contains("apikey") || issue.toLowerCase().contains("api key") || issue.toLowerCase().contains("token")) {
                enhanced.add(issue + " → Fix: Store secrets securely (Vault/ENV).");
            }
            else if (issue.toLowerCase().contains("dependency")) {
                enhanced.add(issue + " → Fix: Upgrade to a secure version.");
            }
            else {
                enhanced.add(issue);
            }
        }

        return enhanced;
    }
}
