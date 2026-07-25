package com.demo;

import org.springframework.web.bind.annotation.*;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.Statement;

@RestController
@RequestMapping("/vulnerable")
public class VulnerableController {

    // 💉 SQL Injection vulnerability
    @GetMapping("/user")
    public String getUser(@RequestParam String id) {
        try {
            Connection conn = DriverManager.getConnection("jdbc:h2:mem:test", "sa", "");
            Statement stmt = conn.createStatement();
            
            // Vulnerability: String concatenation in SQL
            String query = "SELECT * FROM users WHERE id = '" + id + "'";
            ResultSet rs = stmt.executeQuery(query);
            
            return "User found!";
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }

    // 🌐 XSS vulnerability
    @GetMapping("/hello")
    public String sayHello(@RequestParam String name) {
        // Vulnerability: Direct output of user input
        return "<h1>Hello " + name + "</h1>";
    }

    // 🌐 XSS (Response printing)
    @PostMapping("/print")
    public void printData(@RequestBody String data, javax.servlet.http.HttpServletResponse response) throws Exception {
        // Vulnerability: User input directly written to output stream
        response.getWriter().print("Data: " + data);
    }
}
