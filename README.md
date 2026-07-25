# 🔐 RepoGuard — GitHub Repository Vulnerability Scanner

![CI](https://github.com/deepcodex-hub/repoguard/actions/workflows/ci.yml/badge.svg)

RepoGuard is a **backend security scanner** built with Java and Spring Boot that analyzes GitHub repositories for vulnerabilities using **SAST (Static Application Security Testing)** and **SCA (Software Composition Analysis)** techniques.

> Give it any public GitHub repo URL → it downloads the code, scans it, and returns a structured vulnerability report with severity levels and fix recommendations.

---

## 🚀 Features

### 🔍 SAST — Source Code Analysis
Scans Java source files for:

| Vulnerability | Severity | Detection Method |
|---|---|---|
| SQL Injection | **CRITICAL / HIGH** | String concatenation in queries, raw `Statement.execute` |
| Cross-Site Scripting (XSS) | **HIGH / MEDIUM** | Direct response writes, HTML string concatenation |
| Hardcoded Passwords | **HIGH** | Keyword + assignment pattern matching |
| Hardcoded API Keys | **HIGH** | Keyword detection (`apikey`, `api_key`) |
| Hardcoded Tokens | **HIGH** | Keyword + assignment pattern matching |

### 📦 SCA — Dependency Analysis
- Parses `pom.xml` to extract all declared dependencies
- Queries the **NVD (National Vulnerability Database)** API for known CVEs
- Assigns severity based on library risk profile (e.g., Log4j → CRITICAL)
- Uses **in-memory caching** (`ConcurrentHashMap`) to avoid redundant API calls

### 📊 Severity Classification
Every finding is classified as:
- 🔴 **CRITICAL** — Immediate action required (e.g., Log4Shell)
- 🟠 **HIGH** — Serious risk, fix before deployment
- 🟡 **MEDIUM** — Moderate risk, fix in current sprint
- 🟢 **LOW** — Informational, fix when convenient

---

## 🧠 System Architecture

```
User Input: GitHub Repo URL
         ↓
  GithubService (Download + Extract ZIP)
         ↓
  FileService (Filter .java files + pom.xml)
         ↓
    ┌────┴────┐
    ▼         ▼
SASTService  SCAScanner
(Code scan)  (Dep scan via NVD API)
    └────┬────┘
         ↓
  ScanResult (with severitySummary + List<Vulnerability>)
         ↓
  REST API Response (JSON via Swagger UI)
```

---

## 🛠️ Tech Stack

| Technology | Purpose |
|---|---|
| Java 17 | Core language |
| Spring Boot 3.x | REST API framework |
| Springdoc OpenAPI (Swagger) | API documentation & testing |
| NVD CVE API | Dependency vulnerability database |
| JUnit 5 | Unit testing |
| Docker | Containerized deployment |
| GitHub Actions | CI/CD — auto-build and test on push |
| Render | Cloud deployment |

---

## ▶️ Getting Started

### 1. Clone the Repository

```bash
git clone https://github.com/deepcodex-hub/repoguard.git
cd repoguard
```

### 2. Run the Application

```bash
mvn spring-boot:run
```

### 3. Open Swagger UI

```
http://localhost:8080/swagger-ui/index.html
```

### 4. Scan a Repository

```
POST /api/scan?repoUrl=https://github.com/username/repo
```

---

## 📊 Sample Output

```json
{
  "status": "SCAN COMPLETED",
  "totalIssues": 5,
  "severitySummary": {
    "CRITICAL": 1,
    "HIGH": 3,
    "MEDIUM": 1,
    "LOW": 0
  },
  "issues": [
    {
      "type": "SQL_INJECTION",
      "severity": "CRITICAL",
      "fileName": "UserDao.java",
      "lineNumber": 21,
      "description": "Possible SQL Injection via string concatenation in query.",
      "fix": "Use PreparedStatement or parameterized queries."
    },
    {
      "type": "XSS",
      "severity": "HIGH",
      "fileName": "UserController.java",
      "lineNumber": 34,
      "description": "Possible XSS: User input written directly to HTTP response.",
      "fix": "Escape user input using OWASP Java Encoder or HtmlUtils.htmlEscape()."
    },
    {
      "type": "VULNERABLE_DEPENDENCY",
      "severity": "CRITICAL",
      "fileName": "pom.xml",
      "lineNumber": 0,
      "description": "Dependency log4j:1.2.17 may have known CVEs.",
      "fix": "Check https://nvd.nist.gov for CVEs and upgrade to a patched version."
    }
  ]
}
```

---

## 🧪 Running Tests

```bash
mvn test
```

Tests cover all 3 SAST scanners with positive detection cases and false-positive (clean code) cases.

---

## ⚠️ Limitations

- Uses rule-based pattern matching — may produce false positives in some edge cases
- Does not perform AST-based or data-flow analysis (planned for future)
- SCA severity uses heuristics; production tools parse CVSS scores from NVD

---

## 🔮 Future Enhancements

- AST-based vulnerability detection using JavaParser
- Support for Node.js (`package.json`) and Python (`requirements.txt`)
- CVSS score parsing from NVD API response
- Integration with SonarQube

---

## 🌐 Live Demo

Deployed on Render — [RepoGuard Live](https://repoguard.onrender.com/swagger-ui/index.html)

---

*Built as a practical demonstration of SAST + SCA security scanning concepts using Java and Spring Boot.*
