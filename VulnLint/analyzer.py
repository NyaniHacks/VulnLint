import ast
import importlib
import os
from pathlib import Path
from typing import List
from .rules.base_rule import VulnLintBaseRule, VulnLintVisitor

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
                print(f"[VulnLintIssue] Syntax error in {file_path}: {e}")
                return []
            
        issues = []

        for rule in self.rules:
            visitor = rule.visitor()(rule)
            visitor.visitor(tree)
            for issue in visitor.issue:
                issue.file = file_path
                issue.append(issue)

            return issues
        
    def analyze_directory (self, directory: str) -> List [VulnLintIssue]:
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
        