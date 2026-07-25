# ⚠️ Vulnerable Java Demo App

This repository contains a deliberately vulnerable Java application designed for testing security tools like **RepoGuard**.

---

## 🎯 Purpose

This project is intentionally built with common security vulnerabilities to demonstrate how automated tools can detect issues in real-world code.

It is used as a test input for:

👉 **RepoGuard – GitHub Vulnerability Scanner**

---

## 🚨 Included Vulnerabilities

### 💉 1. SQL Injection

```java
String query = "SELECT * FROM users WHERE username = '" + userInput + "'";
```

❌ Unsafe string concatenation
✅ Fix: Use `PreparedStatement`

---

### 🌐 2. Cross-Site Scripting (XSS)

```java
response.getWriter().println("<h1>" + userInput + "</h1>");
```

❌ Direct user input rendering
✅ Fix: Escape output

---

### 🔐 3. Hardcoded Credentials

```java
String password = "admin123";
String apiKey = "dummy_key_123";
```

❌ Sensitive data exposed in code
✅ Fix: Use environment variables

---

## 🧪 How to Use

This repository is intended to be scanned using RepoGuard:

```
POST /api/scan
```

Example:

```
https://github.com/deepcodex-hub/vulnerable-java-demo
```

---

## 📊 Expected Output

When scanned using RepoGuard, you should see:

* SQL Injection detection
* XSS detection
* Sensitive data exposure detection

---

## ⚠️ Disclaimer

This project is intentionally insecure.

❌ Do NOT use this code in production
❌ Do NOT expose real secrets

---

## 🧠 Learning Objective

This demo helps understand:

* Common OWASP vulnerabilities
* How static analysis tools detect issues
* Importance of secure coding practices

---

## 🔗 Related Project

👉 RepoGuard – GitHub Security Scanner

---

## ⭐ Final Note

This repository is part of a security demonstration setup and showcases how vulnerabilities can be identified and mitigated using automated tools.

---
