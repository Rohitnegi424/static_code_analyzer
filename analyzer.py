"""
Static Code Analyzer - Base analyzer classes
This module provides base classes for AST and Token-based analyzers.
"""

import ast
import tokenize
import io
from typing import List, Dict, Any, Optional, Set, Tuple

class Issue:
    """Represents a detected issue in the code."""
    
    def __init__(self, file_path: str, line: int, column: int, 
                 issue_type: str, message: str, severity: str = "medium"):
        self.file_path = file_path
        self.line = line
        self.column = column
        self.issue_type = issue_type
        self.message = message
        self.severity = severity
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert the issue to a dictionary."""
        return {
            "file_path": self.file_path,
            "line": self.line,
            "column": self.column,
            "issue_type": self.issue_type,
            "message": self.message,
            "severity": self.severity
        }


class BaseAnalyzer:
    """Abstract base class for all analyzers."""
    
    def __init__(self, file_path: str):
        self.file_path = file_path
        self.issues: List[Issue] = []
        self.code_lines: List[str] = []
    
    def analyze(self, code: str) -> List[Issue]:
        """Analyze the code and return a list of issues."""
        self.code_lines = code.splitlines()
        return self.issues
    
    def add_issue(self, line: int, column: int, issue_type: str, message: str, severity: str = "medium"):
        """Add an issue to the list of issues."""
        self.issues.append(Issue(self.file_path, line, column, issue_type, message, severity))


class ASTAnalyzer(BaseAnalyzer, ast.NodeVisitor):
    """Base class for AST-based analyzers."""
    
    def analyze(self, code: str) -> List[Issue]:
        """Analyze the code using the Python AST and return a list of issues."""
        super().analyze(code)
        try:
            tree = ast.parse(code)
            self.visit(tree)
        except SyntaxError as e:
            self.add_issue(e.lineno, e.offset, "syntax-error", f"Syntax error: {str(e)}", "high")
        return self.issues
    
    def add_issue_from_node(self, node: ast.AST, issue_type: str, message: str, severity: str = "medium"):
        """Add an issue from an AST node."""
        line = getattr(node, "lineno", 0)
        col = getattr(node, "col_offset", 0)
        self.add_issue(line, col, issue_type, message, severity)


class TokenAnalyzer(BaseAnalyzer):
    """Base class for token-based analyzers."""
    
    def analyze(self, code: str) -> List[Issue]:
        """Analyze the code using Python's tokenize module and return a list of issues."""
        super().analyze(code)
        try:
            tokens = tokenize.tokenize(io.BytesIO(code.encode('utf-8')).readline)
            self.process_tokens(list(tokens))
        except tokenize.TokenError as e:
            self.add_issue(e.args[1][0], 0, "tokenize-error", f"Tokenize error: {str(e)}", "high")
        return self.issues
    
    def process_tokens(self, tokens: List[tokenize.TokenInfo]) -> None:
        """Process the tokens to find issues."""
        # Should be implemented by subclasses
        pass