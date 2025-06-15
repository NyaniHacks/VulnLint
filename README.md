# 🔍 VulnLint - Python Security Linter

![VulnLint Logo](assets/vulnlint-logo.png)

**VulnLint** is a static analysis tool designed to help Python developers detect security vulnerabilities before code reaches production.

> 🧠 *Think of it as a security-focused linter for your Python codebase.*

---

## 🚀 Features

* 🔐 Detects **hardcoded credentials**
* ⚠️ Flags **insecure configurations** and risky imports
* ⚙️ Supports a **custom rule system**
* 🧪 Allows **configurable severity levels** per project

---

## 📦 Installation

Install directly from GitHub:

```bash
pip install git+https://github.com/yourusername/VulnLint.git
```

---

## 🧪 Usage

### 📁 Scan a directory

```bash
vulnlint path/to/your/code
```

### 📄 Scan a single file

```bash
vulnlint path/to/file.py
```

---

## ⚙️ Configuration

Create a `.vulnlint.yaml` file to customize rules and severities:

```yaml
excluded_paths:
  - tests/
  - migrations/

severity_levels:
  CRITICAL: true
  HIGH: true
  MEDIUM: false
  LOW: false
```

---

## 🛠️ Developing New Rules

Want to extend VulnLint with your own rules?

1. Create a new Python file in `vulnlint/rules/`
2. Inherit from `VulnLintBaseRule`
3. Implement the `visitor()` method with your logic

---

## 🧪 Testing the Tool

Create a test file `test.py`:

```python
# This should trigger VulnLint
api_key = "12345-abcdef"
password = "super$ecret"
```

Run the scanner:

```bash
vulnlint test.py
```

You should see alerts for the detected vulnerabilities.

---

## 📜 License

This project is licensed under the [MIT License](LICENSE).

---

