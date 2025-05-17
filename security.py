"""
Static Code Analyzer - Security Analyzer
Detects security issues like SQL injections and hardcoded passwords.
"""

import ast
import re
from typing import List, Dict, Any, Optional

from backend.analyzer import ASTAnalyzer


class SecurityAnalyzer(ASTAnalyzer):
    """Analyzer to detect security issues using AST."""
    
    def __init__(self, file_path: str):
        super().__init__(file_path)
        # Define patterns for dangerous functions and methods
        self.dangerous_functions = {
            'eval': 'Unsafe use of eval() can lead to code execution vulnerabilities',
            'exec': 'Unsafe use of exec() can lead to code execution vulnerabilities',
            'pickle.loads': 'Using pickle.loads() can lead to arbitrary code execution',
            'marshal.loads': 'Using marshal.loads() can lead to arbitrary code execution',
            'yaml.load': 'Using yaml.load() without SafeLoader can lead to arbitrary code execution',
            'subprocess.call': 'subprocess.call with shell=True can be vulnerable to shell injection',
            'subprocess.Popen': 'subprocess.Popen with shell=True can be vulnerable to shell injection',
            'os.system': 'os.system() can be vulnerable to shell injection',
            'os.popen': 'os.popen() can be vulnerable to shell injection',
        }
    
    def visit_Call(self, node: ast.Call):
        """Check for security issues in function calls."""
        # Check for SQL injection
        if self._is_database_query(node):
            self._check_sql_injection(node)
        
        # Check for unsafe use of dangerous functions
        self._check_dangerous_function(node)
        
        # Check for weak cryptography
        self._check_weak_crypto(node)
        
        self.generic_visit(node)
    
    def _is_database_query(self, node: ast.Call) -> bool:
        """Check if the call is a database query."""
        if isinstance(node.func, ast.Attribute):
            methods = ["execute", "executemany", "executequery"]
            if node.func.attr.lower() in methods:
                return True
        return False
    
    def _check_sql_injection(self, node: ast.Call):
        """Check for potential SQL injection."""
        if len(node.args) >= 1:
            # Look for string formatting or concatenation
            arg = node.args[0]
            
            # Check for string concatenation
            if isinstance(arg, ast.BinOp) and isinstance(arg.op, ast.Add):
                self.add_issue_from_node(
                    node, 
                    "sql-injection", 
                    "Potential SQL injection with string concatenation. Use parameterized queries instead.",
                    "high"
                )
            
            # Check for f-strings
            elif isinstance(arg, ast.JoinedStr):
                self.add_issue_from_node(
                    node, 
                    "sql-injection", 
                    "Potential SQL injection with f-strings. Use parameterized queries instead.",
                    "high"
                )
                
            # Check for old-style string formatting
            elif isinstance(arg, ast.BinOp) and isinstance(arg.op, ast.Mod):
                self.add_issue_from_node(
                    node, 
                    "sql-injection", 
                    "Potential SQL injection with % formatting. Use parameterized queries instead.",
                    "high"
                )
                
            # Check for .format() method
            elif isinstance(arg, ast.Call) and isinstance(arg.func, ast.Attribute) and arg.func.attr == 'format':
                self.add_issue_from_node(
                    node, 
                    "sql-injection", 
                    "Potential SQL injection with .format(). Use parameterized queries instead.",
                    "high"
                )
    
    def _check_dangerous_function(self, node: ast.Call):
        """Check for dangerous function usage."""
        func_name = None
        
        # Get the function name
        if isinstance(node.func, ast.Name):
            func_name = node.func.id
        elif isinstance(node.func, ast.Attribute):
            if isinstance(node.func.value, ast.Name):
                # For module.function() calls
                func_name = f"{node.func.value.id}.{node.func.attr}"
        
        if func_name in self.dangerous_functions:
            self.add_issue_from_node(
                node,
                "dangerous-function",
                f"Security risk: {self.dangerous_functions[func_name]}",
                "high"
            )
    
    def _check_weak_crypto(self, node: ast.Call):
        """Check for weak cryptographic algorithms."""
        if isinstance(node.func, ast.Attribute):
            # Check for MD5/SHA1 usage in hashlib
            if isinstance(node.func.value, ast.Name) and node.func.value.id == 'hashlib':
                if node.func.attr in ['md5', 'sha1']:
                    self.add_issue_from_node(
                        node,
                        "weak-crypto",
                        f"Weak cryptographic hash function: {node.func.attr}. Use SHA-256 or better.",
                        "medium"
                    )
    
    def visit_Assign(self, node: ast.Assign):
        """Check for hardcoded credentials."""
        for target in node.targets:
            if isinstance(target, ast.Name):
                name = target.id.lower()
                sensitive_keywords = ['password', 'passwd', 'secret', 'key', 'token', 'api_key', 'apikey']
                
                if any(keyword in name for keyword in sensitive_keywords):
                    if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
                        # We found a hardcoded credential
                        credential = node.value.value
                        if len(credential) > 0 and not credential.startswith(("{", "$", "<%")):
                            # Looks like an actual credential, not a template or placeholder
                            self.add_issue_from_node(
                                node, 
                                "hardcoded-credential", 
                                f"Hardcoded credential detected in variable '{target.id}'",
                                "high"
                            )
        self.generic_visit(node)
    
    def visit_Lambda(self, node: ast.Lambda):
        """Check for security issues in lambda functions."""
        # Lambdas can sometimes hide dangerous code
        self.generic_visit(node)
    
    def visit_Assert(self, node: ast.Assert):
        """Check for assertions that might be removed in production."""
        # Python -O flag removes assert statements
        self.add_issue_from_node(
            node,
            "assert-security",
            "Assert statement might be removed in production (with -O flag), don't use for security checks",
            "medium"
        )
        self.generic_visit(node)