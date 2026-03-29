# 🔐 RepoGuard — GitHub Vulnerability Scanner

RepoGuard is a lightweight backend system that scans GitHub repositories for security vulnerabilities using a combination of **Static Application Security Testing (SAST)** and **Software Composition Analysis (SCA)**.

It is designed to simulate how real-world security tools analyze source code and dependencies to identify potential risks.

---

## 🌐 Live Demo

👉 Try the deployed API here:

```text
https://repoguard-e281.onrender.com/swagger-ui/index.html
```

You can directly test the `/api/scan` endpoint using Swagger UI.

---

## 🚀 Key Features

### 🔍 Static Application Security Testing (SAST)

Analyzes Java source code to detect common vulnerabilities:

* 💉 SQL Injection
* 🌐 Cross-Site Scripting (XSS)
* 🔐 Hardcoded Secrets (passwords, API keys, tokens)

---

### 📦 Software Composition Analysis (SCA)

Scans project dependencies for known vulnerabilities:

* Extracts dependencies from `pom.xml`
* Queries **NVD (National Vulnerability Database)**
* Uses caching for improved performance

---

### ⚡ Intelligent Processing

* Filters relevant files (`.java`, `pom.xml`)
* Ignores unnecessary directories (`.git`, `target`, etc.)
* Reduces redundant API calls using in-memory caching

---

### 🌐 API & Interface

* REST API built with Spring Boot
* Interactive testing using Swagger UI

---

## 🧠 System Workflow

```text
User → GitHub Repository URL
        ↓
Repository Downloaded (ZIP-based)
        ↓
File Filtering (.java + pom.xml)
        ↓
   ├── SAST Analysis (code-level)
   └── SCA Analysis (dependency-level)
        ↓
Fix Suggestions Added
        ↓
Results Returned via API (Swagger UI)
```

---

## 🔥 Robust Features

* Handles GitHub URLs with `.git` suffix and trailing slashes
* Supports multiple branch formats (`main`, `master`, etc.)
* Uses ZIP-based repository download for cloud compatibility
* Encodes external API requests to prevent failures
* Provides structured error responses using global exception handling
* Designed to handle real-world GitHub repository variations and edge cases

---

## 🚀 Key Improvements

* Fixed 500 errors caused by improper URL parsing
* Improved repository extraction logic for ZIP archives
* Added global exception handling for better debugging
* Enhanced fix suggestion consistency (API key detection)
* Made system fully compatible with cloud deployment (Render + Docker)

---

## 🛠️ Tech Stack

* Java 17
* Spring Boot
* Swagger (Springdoc OpenAPI)
* NVD API (CVE database)
* Git / GitHub
* Docker
* Render (Deployment)

---

## ▶️ Getting Started

### 1️⃣ Clone the Repository

```bash
git clone https://github.com/deepcodex-hub/repoguard.git
cd repoguard
```

---

### 2️⃣ Run the Application

```bash
mvn spring-boot:run
```

---

### 3️⃣ Open Swagger UI

```text
http://localhost:8080/swagger-ui/index.html
```

---

### 4️⃣ Test the API

Endpoint:

```text
POST /api/scan
```

Example Input:

```text
https://github.com/spring-projects/spring-petclinic
```

---

## 📊 Sample Output

```json
{
  "status": "SCAN COMPLETED",
  "totalIssues": 3,
  "issues": [
    "Possible SQL Injection in file: UserService.java → Fix: Use PreparedStatement",
    "Possible XSS in file: Controller.java → Fix: Escape user input",
    "Scanned dependency: log4j:1.2.17 → Fix: Upgrade version"
  ]
}
```

---

## ⚠️ Limitations

* Uses rule-based pattern matching (may produce false positives)
* Does not perform deep AST or data-flow analysis
* Dependency resolution is basic (no full transitive analysis)

---

## 🔮 Future Enhancements

* AST-based vulnerability detection
* Advanced dependency resolution
* Support for Node.js (`package.json`)
* Integration with tools like SonarQube

---

## 🧪 Testing Strategy

The system was tested using:

* Real-world open-source projects
* A custom vulnerable repository designed to validate detection logic

---

## ⭐ Final Note

RepoGuard demonstrates a practical approach to repository-level security analysis by combining code scanning and dependency vulnerability detection in a modular and scalable architecture, with strong focus on real-world robustness and deployment readiness.

---
