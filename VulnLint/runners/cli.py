import argparse
import json
import os
import sys
from typing import List
from ..analyzer import VulnLintAnalyzer
from ..config import load_config
from ..rules.base_rule import VulnLintIssue

def print_vulnlint_reports(issues: List[VulnLintIssue], format='text'):
    if format == "json":
        print(json.dumps([issue.to_dict() for issue in issues], indent=2))
    else:
        print(f"\nVulnLint Security Report")
        print("=" * 40)
        for issue in issues:
            print(f"[{issue.severity}] {issue.file}:{issue.lineno}")
            print (f" {issue.message} (Rule: {issue.rule_id})")
            print()

def main():
    parser = argparse.ArgumentParser(description='VulnLint - Python Security Scanner')
    parser.add_argument('target', help='File or directory to scan')
    parser.add_argument('--config', '-c', help='Path to configuration file')
    parser.add_argument('--format', '-f', choices=['text', 'json'], default='text')
    parser.add_argument('--verbose', '-v', action='store_true', help='Show detailed output')

    args =  parser.parse_args()

    config = load_config(args.config)
    analyzer = VulnLintAnalyzer(config)

    if os.path.isfile(args.target):
        issues = analyzer.analyze_file(args.target)
    else:
        issues = analyzer.analyze_directory(args.target)
    severity_filter = config.get('serity_levels', {})
    if severity_filter:
        issues = [issue for issue in issues if severity_filter.get(issue.severity, True)]

    print_vulnlint_reports(issues, args.format)

    if issues and any(issue.severity in ['HIGH', 'MEDIUM'] for issue in issues):
        sys.exit(1)

if __name__ == '__main__':
    main()