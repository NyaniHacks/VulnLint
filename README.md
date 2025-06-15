# Building **VulnLint**: A Python SAST Tool for macOS with VS Code and GitHub

Let's create your SAST tool with the correct name from the beginning. I'll adapt all previous instructions to use "VulnLint" consistently.

## Step 1: Project Setup in VS Code

1. **Create new project folder**:
   ```bash
   mkdir vulnlint
   cd vulnlint
   ```

2. **Initialize Git**:
   ```bash
   git init
   ```

3. **Open in VS Code**:
   ```bash
   code .
   ```

## Step 2: GitHub Repository Setup

1. **Create new repo on GitHub** named "VulnLint"
2. **Connect local repo** (in VS Code terminal):
   ```bash
   git remote add origin https://github.com/yourusername/VulnLint.git
   ```

## Step 3: Python Environment

1. **Create virtual environment**:
   ```bash
   python -m venv .venv
   source .venv/bin/activate
   ```

2. **Install requirements**:
   ```bash
   touch requirements.txt
   echo "pyyaml" > requirements.txt
   pip install -r requirements.txt
   ```

## Step 4: Project Structure

Create these files in VS Code Explorer:

```
VulnLint/
├── vulnlint/
│   ├── __init__.py
│   ├── analyzer.py
│   ├── config.py
│   ├── rules/
│   │   ├── __init__.py
│   │   ├── base_rule.py
│   │   └── hardcoded_passwords.py
│   └── runners/
│       └── cli.py
├── tests/
│   └── __init__.py
├── .gitignore
├── README.md
├── requirements.txt
└── setup.py
```

## Step 5: Core Implementation Files

1. **`setup.py`** (updated with VulnLint name):
```python
from setuptools import setup, find_packages

setup(
    name="vulnlint",
    version="0.1.0",
    packages=find_packages(),
    install_requires=[
        'pyyaml',
    ],
    entry_points={
        'console_scripts': [
            'vulnlint=vulnlint.runners.cli:main',
        ],
    },
)
```

2. **`vulnlint/__init__.py`**:
```python
__version__ = "0.1.0"
__tool_name__ = "VulnLint"
```

3. **`.gitignore`**:
```
.venv/
__pycache__/
*.py[cod]
*$py.class
.python-version
.pytest_cache/
.mypy_cache/
.DS_Store
```

## Step 6: Base Rule System

1. **`vulnlint/rules/base_rule.py`**:
```python
import ast

class VulnLintIssue:
    def __init__(self, lineno, col_offset, message, severity='MEDIUM', rule_id=None):
        self.lineno = lineno
        self.col_offset = col_offset
        self.message = message
        self.severity = severity
        self.rule_id = rule_id
        self.file = None

    def to_dict(self):
        return {
            'tool': 'VulnLint',
            'file': self.file,
            'line': self.lineno,
            'column': self.col_offset,
            'message': self.message,
            'severity': self.severity,
            'rule_id': self.rule_id
        }

class VulnLintBaseRule:
    id = None
    description = None
    severity = 'MEDIUM'
    
    def visitor(self):
        raise NotImplementedError
        
class VulnLintVisitor(ast.NodeVisitor):
    def __init__(self, rule):
        self.issues = []
        self.rule = rule
        
    def add_issue(self, node, message, severity=None):
        self.issues.append(VulnLintIssue(
            lineno=node.lineno,
            col_offset=node.col_offset,
            message=message,
            severity=severity or self.rule.severity,
            rule_id=self.rule.id
        ))
```

## Step 7: First Security Rule

**`vulnlint/rules/hardcoded_passwords.py`**:
```python
import ast
from .base_rule import VulnLintBaseRule, VulnLintVisitor

class HardcodedPasswordRule(VulnLintBaseRule):
    id = 'VL-PWD-001'
    description = 'Hardcoded password detected'
    severity = 'HIGH'
    keywords = ['password', 'passwd', 'pwd', 'secret', 'api_key']

    def visitor(self):
        class Visitor(VulnLintVisitor):
            def visit_Assign(self, node):
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        if any(keyword in target.id.lower() for keyword in self.rule.keywords):
                            if isinstance(node.value, ast.Str):
                                self.add_issue(node, 
                                    f"Hardcoded credentials found in variable '{target.id}'")
                self.generic_visit(node)
                
        return Visitor
```

## Step 8: Analyzer Core

**`vulnlint/analyzer.py`**:
```python
import ast
import importlib
import inspect
import os
from pathlib import Path
from typing import List
from .rules.base_rule import VulnLintBaseRule, VulnLintIssue

class VulnLintAnalyzer:
    def __init__(self, config=None):
        self.config = config or {}
        self.rules = self._load_rules()
        
    def _load_rules(self) -> List[VulnLintBaseRule]:
        rules = []
        rules_dir = Path(__file__).parent / 'rules'
        
        for file in rules_dir.glob('*.py'):
            if file.name.startswith('_'):
                continue
                
            module_name = f"vulnlint.rules.{file.stem}"
            try:
                module = importlib.import_module(module_name)
                
                for name, obj in inspect.getmembers(module):
                    if inspect.isclass(obj) and name.endswith('Rule') and obj != VulnLintBaseRule:
                        rule = obj()
                        if self.config.get('rules', {}).get(rule.id, {}).get('enabled', True):
                            rules.append(rule)
            except ImportError as e:
                print(f"[VulnLint] Warning: Failed to load rule from {file}: {e}")
                
        return rules
    
    def analyze_file(self, file_path: str) -> List[VulnLintIssue]:
        with open(file_path, 'r', encoding='utf-8') as f:
            try:
                tree = ast.parse(f.read(), filename=file_path)
            except SyntaxError as e:
                print(f"[VulnLint] Syntax error in {file_path}: {e}")
                return []
                
        issues = []
        
        for rule in self.rules:
            visitor = rule.visitor()(rule)
            visitor.visit(tree)
            for issue in visitor.issues:
                issue.file = file_path
                issues.append(issue)
                
        return issues
    
    def analyze_directory(self, directory: str) -> List[VulnLintIssue]:
        issues = []
        excluded_paths = self.config.get('excluded_paths', [])
        
        for root, _, files in os.walk(directory):
            if any(excluded in root for excluded in excluded_paths):
                continue
                
            for file in files:
                if file.endswith('.py'):
                    file_path = os.path.join(root, file)
                    issues.extend(self.analyze_file(file_path))
                    
        return issues
```

## Step 9: CLI Runner

**`vulnlint/runners/cli.py`**:
```python
import argparse
import json
import os
import sys
from typing import List
from ..analyzer import VulnLintAnalyzer
from ..config import load_config
from ..rules.base_rule import VulnLintIssue

def print_vulnlint_report(issues: List[VulnLintIssue], format='text'):
    if format == 'json':
        print(json.dumps([issue.to_dict() for issue in issues], indent=2))
    else:
        print(f"\nVulnLint Security Report")
        print("=" * 40)
        for issue in issues:
            print(f"[{issue.severity}] {issue.file}:{issue.lineno}")
            print(f"  {issue.message} (Rule: {issue.rule_id})")
            print()

def main():
    parser = argparse.ArgumentParser(description='VulnLint - Python Security Scanner')
    parser.add_argument('target', help='File or directory to scan')
    parser.add_argument('--config', '-c', help='Path to config file')
    parser.add_argument('--format', '-f', choices=['text', 'json'], default='text')
    parser.add_argument('--verbose', '-v', action='store_true', help='Show detailed output')
    
    args = parser.parse_args()
    
    config = load_config(args.config)
    analyzer = VulnLintAnalyzer(config)
    
    if os.path.isfile(args.target):
        issues = analyzer.analyze_file(args.target)
    else:
        issues = analyzer.analyze_directory(args.target)
    
    severity_filter = config.get('severity_levels', {})
    if severity_filter:
        issues = [issue for issue in issues if severity_filter.get(issue.severity, True)]
    
    print_vulnlint_report(issues, args.format)
    
    if issues and any(issue.severity in ['HIGH', 'MEDIUM'] for issue in issues):
        sys.exit(1)

if __name__ == '__main__':
    main()
```

## Step 10: Configuration

**`vulnlint/config.py`**:
```python
import yaml
from pathlib import Path
from typing import Dict, Any

DEFAULT_CONFIG = {
    'excluded_paths': ['tests/', 'venv/', '.venv/'],
    'severity_levels': {
        'CRITICAL': True,
        'HIGH': True,
        'MEDIUM': True,
        'LOW': False
    },
    'rules': {
        # Will be populated automatically
    }
}

def load_config(config_path: str = None) -> Dict[str, Any]:
    if config_path and Path(config_path).exists():
        with open(config_path) as f:
            user_config = yaml.safe_load(f) or {}
            return {**DEFAULT_CONFIG, **user_config}
    return DEFAULT_CONFIG
```

## Step 11: README.md

```markdown
# VulnLint - Python Security Linter

![VulnLint Logo](https://via.placeholder.com/150?text=VulnLint)

A static analysis tool for finding security vulnerabilities in Python code.

## Features

- Detects hardcoded credentials
- Identifies potential security misconfigurations
- Custom rule system
- Configurable severity levels

## Installation

```bash
pip install git+https://github.com/yourusername/VulnLint.git
```

## Usage

Scan a directory:
```bash
vulnlint path/to/your/code
```

Scan a single file:
```bash
vulnlint path/to/file.py
```

## Configuration

Create `.vulnlint.yaml`:
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

## Development

To add new rules:
1. Create new Python files in `vulnlint/rules/`
2. Inherit from `VulnLintBaseRule`
3. Implement the `visitor()` method
```

## Step 12: Commit and Push

1. **Stage all files** in VS Code
2. **Commit** with message "Initial VulnLint implementation"
3. **Push** to GitHub

## Step 13: Test Your Tool

1. Create `test.py`:
```python
# This should trigger VulnLint
api_key = "12345-abcdef"
password = "super$ecret"
```

2. Run scan:
```bash
vulnlint test.py
```

You should see VulnLint report the security issues!
