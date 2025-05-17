import ast
from typing import Set, Dict

from backend.analyzer import ASTAnalyzer

class UnusedVariablesAnalyzer(ASTAnalyzer):
    def __init__(self, file_path: str):
        super().__init__(file_path)
        self.assigned_vars: Dict[str, ast.Assign] = {}
        self.used_vars: Set[str] = set()

    def visit_Assign(self, node: ast.Assign):
        for target in node.targets:
            if isinstance(target, ast.Name):
                self.assigned_vars[target.id] = node
        self.generic_visit(node)

    def visit_Name(self, node: ast.Name):
        if isinstance(node.ctx, ast.Load):
            self.used_vars.add(node.id)
        self.generic_visit(node)

    def analyze(self, code: str) -> list:
        super().analyze(code)
        for var, node in self.assigned_vars.items():
            if var not in self.used_vars:
                self.add_issue_from_node(
                    node,
                    "unused-variable",
                    f"Unused variable: '{var}'"
                )
        return self.issues