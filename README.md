# 🔐 RepoGuard — GitHub Repository Vulnerability Scanner

[![CI](https://github.com/deepcodex-hub/repoguard/actions/workflows/ci.yml/badge.svg)](https://github.com/deepcodex-hub/repoguard/actions/workflows/ci.yml)

RepoGuard is a **backend security scanner** built with **Java 17 and Spring Boot** that analyzes source code repositories for vulnerabilities using **SAST (Static Application Security Testing)** and **SCA (Software Composition Analysis)**.

> Point it at a repo → it downloads the code, scans it, and returns a structured vulnerability report with severity levels and fix recommendations — via REST API, a web dashboard, or as a GitHub Action.

---

## 🚀 Features

### 🔍 SAST — Source Code Analysis

RepoGuard performs **AST-based analysis** (via JavaParser) rather than plain regex/pattern matching, scanning Java source for:

| Vulnerability              | Severity            | Detection Method                                          |
| --------------------------- | -------------------- | ----------------------------------------------------------- |
| SQL Injection               | **CRITICAL / HIGH**  | AST-level detection of string-built queries, raw `Statement.execute` |
| Cross-Site Scripting (XSS)  | **HIGH / MEDIUM**    | Direct response writes, HTML string concatenation           |
| Hardcoded Passwords         | **HIGH**             | Keyword + assignment pattern matching                       |
| Hardcoded API Keys          | **HIGH**             | Keyword detection (`apikey`, `api_key`)                     |
| Hardcoded Tokens            | **HIGH**             | Keyword + assignment pattern matching                       |

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

### 🖥️ Web Dashboard

A Thymeleaf-powered dashboard for browsing scan results visually, in addition to the raw JSON API.

### ⚙️ GitHub Action

RepoGuard ships as a **Docker-based GitHub Action** so it can run directly in CI:

```yaml
- name: Run RepoGuard Scan
  uses: deepcodex-hub/RepoGuard@main
  with:
    path: '.'
```

This runs the scanner against the checked-out repository (`--cli.repoPath`) as part of your pipeline — no separate deployment needed.

---

## 🧠 System Architecture

```
User Input: GitHub Repo URL / Local Path
         ↓
  GithubService (Download + Extract ZIP)      [for remote scans]
  or direct filesystem path                    [for CI/local scans]
         ↓
  FileService (Filter .java files + pom.xml)
         ↓
    ┌────┴────┐
    ▼         ▼
SASTService  SCAScanner
(AST scan    (Dep scan via
via JavaParser)   NVD API)
    └────┬────┘
         ↓
  ScanResult (severitySummary + List<Vulnerability>)
         ↓
  REST API (JSON) · Web Dashboard (Thymeleaf) · GitHub Action output
```

---

## 🛠️ Tech Stack

| Technology                  | Purpose                             |
| ---------------------------- | ------------------------------------ |
| Java 17                      | Core language                        |
| Spring Boot 3.2               | REST API + web framework            |
| JavaParser                   | AST-based source code analysis      |
| Thymeleaf                    | Web dashboard UI                    |
| Springdoc OpenAPI (Swagger)   | API documentation & testing         |
| NVD CVE API                  | Dependency vulnerability database   |
| Lombok                        | Boilerplate reduction               |
| JUnit 5                       | Unit testing                        |
| Docker                        | Containerized deployment + GitHub Action |
| GitHub Actions                | CI/CD — auto-build, test, and scan on push |
| Render                        | Cloud deployment                    |

---

## ▶️ Getting Started

### 1. Clone the Repository

```bash
git clone https://github.com/deepcodex-hub/RepoGuard.git
cd RepoGuard
```

### 2. Run the Application

```bash
mvn spring-boot:run
```

### 3. Open the Dashboard or Swagger UI

- Web Dashboard: `http://localhost:8080/`
- Swagger UI: `http://localhost:8080/swagger-ui/index.html`

### 4. Scan a Repository

```
POST /api/scan?repoUrl=https://github.com/username/repo
```

### 5. (Optional) Use as a GitHub Action

Add to your workflow:

```yaml
- name: Run RepoGuard Scan
  uses: deepcodex-hub/RepoGuard@main
  with:
    path: '.'
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

Tests cover all SAST scanners with positive detection cases and false-positive (clean code) cases.

---

## ⚠️ Limitations

- SAST is Java-only for now
- SCA severity uses heuristics; production-grade tools parse full CVSS vectors from NVD
- Dependency lookups depend on NVD API availability/rate limits

---

## 🔮 Future Enhancements

- Support for Node.js (`package.json`) and Python (`requirements.txt`)
- CVSS score parsing from NVD API response
- Integration with SonarQube
- Data-flow analysis (beyond AST pattern matching)

---

## 🌐 Live Demo

Deployed on Render — [RepoGuard Live](https://repoguard-e281.onrender.com/)

---

*Built as a practical demonstration of SAST + SCA security scanning, AST-based analysis, and CI/CD integration using Java and Spring Boot.*
