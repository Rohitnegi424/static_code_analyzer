"""
Static Code Analyzer - Dead Code Analyzer
Detects code that can never run, like code after return statements.
"""

import ast
from typing import List, Optional

from backend.analyzer import ASTAnalyzer


class DeadCodeAnalyzer(ASTAnalyzer):
    """Analyzer to detect dead code using AST."""
    
    def __init__(self, file_path: str):
        super().__init__(file_path)
        self.current_function = None
        self.has_return = False
        self.function_stack = []  # For nested functions
        
    def visit_FunctionDef(self, node: ast.FunctionDef):
        """Check for code after return statements."""
        # Save current state before diving into function
        self.function_stack.append((self.current_function, self.has_return))
        self.current_function = node
        self.has_return = False
        
        # First, check for unreachable code within the body
        self._check_unreachable_statements(node.body)
        
        # Continue normal visit
        self.generic_visit(node)
        
        # Restore state when exiting function
        self.current_function, self.has_return = self.function_stack.pop()
    
    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef):
        """Handle async functions just like regular functions."""
        self.visit_FunctionDef(node)
    
    def _check_unreachable_statements(self, statements: List[ast.stmt]) -> None:
        """Check for statements that are unreachable after flow control breaks."""
        found_terminator = False
        terminator_node = None
        
        for stmt in statements:
            if found_terminator:
                self.add_issue_from_node(
                    stmt, 
                    "unreachable-code", 
                    f"Unreachable code after {self._get_terminator_type(terminator_node)}"
                )
                continue
                
            if self._is_terminator(stmt):
                found_terminator = True
                terminator_node = stmt
            
            # Check for unreachable code inside if/else blocks
            if isinstance(stmt, ast.If):
                # Check true branch
                self._check_unreachable_statements(stmt.body)
                
                # Check else branch
                if stmt.orelse:
                    self._check_unreachable_statements(stmt.orelse)
            
            # Check for unreachable code in loops
            elif isinstance(stmt, (ast.For, ast.While, ast.AsyncFor)):
                self._check_unreachable_statements(stmt.body)
                if stmt.orelse:
                    self._check_unreachable_statements(stmt.orelse)
            
            # Check for unreachable code in try/except/finally
            elif isinstance(stmt, ast.Try):
                self._check_unreachable_statements(stmt.body)
                for handler in stmt.handlers:
                    self._check_unreachable_statements(handler.body)
                if stmt.orelse:
                    self._check_unreachable_statements(stmt.orelse)
                if stmt.finalbody:
                    self._check_unreachable_statements(stmt.finalbody)
            
            # Check for unreachable code in with blocks
            elif isinstance(stmt, (ast.With, ast.AsyncWith)):
                self._check_unreachable_statements(stmt.body)
    
    def _is_terminator(self, node: ast.stmt) -> bool:
        """Check if a statement terminates the flow of execution."""
        return (
            isinstance(node, ast.Return) or
            isinstance(node, ast.Raise) or
            isinstance(node, ast.Break) or
            isinstance(node, ast.Continue) or
            (
                isinstance(node, ast.Expr) and 
                isinstance(node.value, ast.Call) and
                self._is_exit_function(node.value)
            )
        )
    
    def _is_exit_function(self, call_node: ast.Call) -> bool:
        """Check if a function call is to a function like exit() or sys.exit()."""
        if isinstance(call_node.func, ast.Name):
            return call_node.func.id in ('exit', 'quit')
        elif isinstance(call_node.func, ast.Attribute):
            if isinstance(call_node.func.value, ast.Name) and call_node.func.value.id == 'sys':
                return call_node.func.attr == 'exit'
        return False
    
    def _get_terminator_type(self, node: ast.stmt) -> str:
        """Get a human-readable description of the terminator statement."""
        if isinstance(node, ast.Return):
            return "return statement"
        elif isinstance(node, ast.Raise):
            return "raise statement"
        elif isinstance(node, ast.Break):
            return "break statement"
        elif isinstance(node, ast.Continue):
            return "continue statement"
        elif isinstance(node, ast.Expr) and isinstance(node.value, ast.Call):
            return "exit function call"
        return "terminator statement"
    
    def visit_If(self, node: ast.If):
        """Check for impossible conditions."""
        # Check for simple cases like "if False:"
        if isinstance(node.test, ast.Constant) and isinstance(node.test.value, bool):
            if node.test.value is False:
                self.add_issue_from_node(
                    node, 
                    "dead-code", 
                    "Condition is always False, code will never execute"
                )
            elif len(node.orelse) > 0:
                # if True: ... else: ... -> else block is dead
                for stmt in node.orelse:
                    self.add_issue_from_node(
                        stmt, 
                        "dead-code", 
                        "Condition is always True, else block will never execute"
                    )
        
        self.generic_visit(node)
    
    def visit_While(self, node: ast.While):
        """Check for loops that will never execute or exit."""
        if isinstance(node.test, ast.Constant) and isinstance(node.test.value, bool):
            if node.test.value is False:
                self.add_issue_from_node(
                    node, 
                    "dead-code", 
                    "While loop condition is always False, loop will never execute"
                )
        
        self.generic_visit(node)