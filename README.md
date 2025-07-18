# 🛡️ XYZ-Scan 🛡️

**From CyberXYZ Security Inc., our research team looks for the next 0-Day vulnerabilities in collaboration with Cork Institute for Technology (CIT).**

[![MIT License](https://img.shields.io/badge/License-MIT-green.svg)](https://choosealicense.com/licenses/mit/)

## 🚀 Overview

The XYZ-Scan is a powerful command-line interface that allows developers and security professionals to scan their projects for known vulnerabilities. It leverages the comprehensive XYZ Vulnerability Database to provide real-time security insights.

## ✨ Features

-   **Vulnerability Scanning**: Scan your projects for vulnerabilities using a variety of methods.
-   **Package Auditing**: Audit your dependencies for known security issues.
-   **Exploit Information**: Get information about known exploits for discovered vulnerabilities.
-   **Multi-Ecosystem Support**: Scan projects in various ecosystems, including Python and Go.

## 🛠️ Installation

You can install the XYZ-Scan using `pip` or `uv`:

```bash
pip install xyz-scan
```

or

```bash
uv pip install xyz-scan
```

**Note:** To use the Go auditing features, you will also need to install `depsdev`:

```bash
go install github.com/edoardottt/depsdev/cmd/depsdev@latest
```

## 👨‍💻 Usage

To get started, you'll need to log in to your CyberXYZ account:

```bash
xyz login
```

Once logged in, you can use the following commands to check your projects for vulnerabilities.

### `info`

Display information about the XYZ Vulnerability API.

```bash
xyz info
```

### `vuln`

Search for a specific vulnerability by ID (e.g., CVE, GHSA).

```bash
xyz vuln CVE-2021-44228
```

**Options:**

*   `-x`, `--exploits`: Include exploit information.
*   `--affected`: Show affected packages.
*   `--json`: Output as JSON.

### `package`

Search for vulnerabilities affecting a specific package.

```bash
xyz package requests -e pypi -v 2.25.1
```

**Options:**

*   `-e`, `--ecosystem`: Filter by ecosystem (e.g., npm, pypi, maven).
*   `-v`, `--version`: Filter by package version.
*   `-s`, `--severity`: Filter by severity (critical, high, medium, low).
*   `-x`, `--exploits`: Include exploit information.
*   `--limit`: Maximum results to return.
*   `--json`: Output as JSON.

### `scan`

Scan installed packages for vulnerabilities.

```bash
xyz scan --python --npm
```

**Options:**

*   `--python`: Scan Python packages.
*   `--npm`: Scan npm packages.
*   `-i`, `--system`: Scan system packages.
*   `--java`: Scan Java packages.
*   `--go`: Scan Go packages.
*   `--php`: Scan PHP packages.
*   `--microsoft`: Scan Microsoft packages.
*   `--all`: Scan all package types.
*   `-x`, `--exploits`: Include exploit information.
*   `--json`: Output as JSON.
*   `--list-packages`: Only list installed packages, do not scan for vulnerabilities.

### `audit`

Audit local development environments.

#### `python`

Audit Python environment for vulnerabilities and dependency tree.

```bash
xyz audit python
```

**Options:**

*   `--json`: Output audit results as JSON.

#### `go`

Audit Go modules.

```bash
xyz audit go
```

**Options:**

*   `--json`: Output audit results as JSON.

### `recent`

Show recent vulnerabilities.

```bash
xyz recent --days 7
```

**Options:**

*   `--days`: Number of days to look back.
*   `--limit`: Maximum results to return.
*   `-x`, `--exploits`: Include exploit information.
*   `--json`: Output as JSON.

### `stats`

Show database and API statistics.

```bash
xyz stats
```

## 🙏 Credits

This tool was developed by the CyberXYZ Security team.

## 📄 License

The XYZ-Scan is licensed under a commercial license. See the [LICENSE](LICENSE) file for more details.
