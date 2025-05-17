"""
Static Code Analyzer - TODO Comments Analyzer
Detects TODO and FIXME comments in the code using the tokenize module.
"""

import tokenize
import re
from typing import List

from backend.analyzer import TokenAnalyzer


class TodoCommentsAnalyzer(TokenAnalyzer):
    """Analyzer to detect TODO and FIXME comments using tokenize."""
    
    def __init__(self, file_path: str):
        super().__init__(file_path)
        self.todo_pattern = re.compile(
            r'\b(TODO|FIXME|XXX|BUG|HACK|NOTE|OPTIMIZE|REVIEW)\b\s*:?(.+)?',
            re.IGNORECASE
        )
        
    def process_tokens(self, tokens: List[tokenize.TokenInfo]) -> None:
        """Process tokens to find TODO and FIXME comments."""
        for token in tokens:
            if token.type == tokenize.COMMENT:
                self._check_comment(token)
    
    def _check_comment(self, token: tokenize.TokenInfo) -> None:
        """Check a comment token for TODO/FIXME patterns."""
        comment_text = token.string[1:].strip()  # Remove '#' and strip whitespace
        match = self.todo_pattern.search(comment_text)
        
        if match:
            todo_type = match.group(1).upper()
            message = match.group(2).strip() if match.group(2) else ""
            
            # Determine severity based on comment type
            severity = "low"
            if todo_type in ["FIXME", "BUG"]:
                severity = "medium"
            elif todo_type in ["XXX", "HACK"]:
                severity = "high"
            
            issue_type = f"{todo_type.lower()}-comment"
            full_message = f"{todo_type} comment found: {message}" if message else f"{todo_type} comment found"
            
            # Add the issue
            self.add_issue(
                token.start[0],  # Line number
                token.start[1],  # Column number
                issue_type,
                full_message,
                severity
            )
            
            # Warning if no description provided
            if not message:
                self.add_issue(
                    token.start[0], 
                    token.start[1], 
                    issue_type + "-warning",
                    f"{todo_type} comment found but no description provided.",
                    "low"
                )