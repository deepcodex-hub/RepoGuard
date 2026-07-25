package com.demo;

public class Config {

    // 🔐 Vulnerability: Hardcoded password
    private String DB_PASSWORD = "super_secret_password_123";

    // 🔐 Vulnerability: API Key exposure
    private String apiKey = "DUMMY_API_KEY_FOR_TESTING_PURPOSES";

    // 🔐 Vulnerability: Token exposure
    private String GITHUB_TOKEN = "DUMMY_GITHUB_TOKEN_FOR_TESTING";

    public void connect() {
        System.out.println("Connecting with: " + DB_PASSWORD);
        System.out.println("API Key: " + apiKey);
        System.out.println("Token: " + GITHUB_TOKEN);
    }
}
