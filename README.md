# RepoGuard

RepoGuard is an automated security scanning tool for GitHub repositories. It performs Static Application Security Testing (SAST) and Software Composition Analysis (SCA) to identify vulnerabilities and suggest fixes.

## Features

- **GitHub Integration**: Scan repositories directly from URL.
- **SAST (Static Application Security Testing)**: Detect common vulnerabilities like SQL Injection, XSS, and Sensitive Data exposure.
- **SCA (Software Composition Analysis)**: Scan dependencies for known vulnerabilities using NVD data.
- **Fix Suggestions**: Automated suggestions for fixing identified security issues.
- **Swagger Documentation**: Interactive API documentation.

## Getting Started

### Prerequisites

- Java 17
- Maven

### Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/repoguard.git
   ```
2. Navigate to the project directory:
   ```bash
   cd repoguard
   ```
3. Build the project:
   ```bash
   mvn clean install
   ```

### Running the Application

```bash
mvn spring-boot:run
```

The API will be available at `http://localhost:8080`.
Swagger UI: `http://localhost:8080/swagger-ui.html`
