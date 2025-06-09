import ast
class VulnLintIssue:
    def __init__(self, lineno, col_offset, message, severity='MEDIUM', rule_id=None):
        self.lineno = lineno
        self.col_offset = col_offset
        self.message = message
        self.severity = severity
        self.rule_id = rule_id
        self.file = None

    def to_dict (self):
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

    def add_issue(self,node, message, severity=None):
        self.issues.append(VulnLintIssue(
            lineno=node.lineo,
            col_offset=node.col_offset,
            message=message,
            severity=severity or self.rule.severity,
            rule_id=self.rule.id
        )
                              ) 