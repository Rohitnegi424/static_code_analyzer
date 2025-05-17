"""
Static Code Analyzer - Unused Imports Analyzer
Detects imports that are never used in the code.
"""

import ast
from typing import Dict, Set

from backend.analyzer import ASTAnalyzer


class UnusedImportsAnalyzer(ASTAnalyzer):
    """Analyzer to detect unused imports using AST."""
    
    def __init__(self, file_path: str):
        super().__init__(file_path)
        self.imported_names: Dict[str, ast.Import] = {}
        self.imported_from_names: Dict[str, ast.ImportFrom] = {}
        self.used_names: Set[str] = set()
        
    def visit_Import(self, node: ast.Import):
        """Record imports."""
        for name in node.names:
            alias = name.asname or name.name
            self.imported_names[alias] = node
        self.generic_visit(node)
        
    def visit_ImportFrom(self, node: ast.ImportFrom):
        """Record from imports."""
        for name in node.names:
            if name.name == '*':
                # Can't track star imports easily
                continue
            alias = name.asname or name.name
            self.imported_from_names[alias] = node
        self.generic_visit(node)
        
    def visit_Name(self, node: ast.Name):
        """Record name usage."""
        if isinstance(node.ctx, ast.Load):
            self.used_names.add(node.id)
        self.generic_visit(node)
        
    def visit_Attribute(self, node: ast.Attribute):
        """Record attribute usage for detecting module imports."""
        if isinstance(node.value, ast.Name):
            self.used_names.add(node.value.id)
        self.generic_visit(node)
    
    def analyze(self, code: str) -> list:
        """Analyze the code and detect unused imports."""
        super().analyze(code)
        
        # Check for unused imports
        for name, node in self.imported_names.items():
            if name not in self.used_names:
                self.add_issue_from_node(node, "unused-import", f"Unused import: '{name}'")
                
        # Check for unused from imports
        for name, node in self.imported_from_names.items():
            if name not in self.used_names:
                self.add_issue_from_node(node, "unused-import", f"Unused import: '{name}'")
                
        return self.issues