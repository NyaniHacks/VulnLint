import ast
from .base_rule import VulnLintBaseRule, VulnLintVisitor

class HardcodedPasswordRule(VulnLintBaseRule):
    id = 'VL-PWD-001'
    description = 'Hardcoded password detected'
    severity = 'HIGH'
    keywords = ['password', 'passwd', 'pwd', 'secret', 'api_key']

    def visitor(self):
        class visitor(VulnLintVisitor):
            def visit_Assign(self, node):
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        if any(keyword in target.id.lower() for keywprd in self.rule.keywords):
                            if isinstance(node.value, ast.Str):
                                self.add_issue(node
                                               f"Hardcoded credentials found in variable '{target.id}'")
                                
                self.generic_visit(node)
        
        return visitor

