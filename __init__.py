from backend.analyzers.unused_imports import UnusedImportsAnalyzer
from backend.analyzers.dead_code import DeadCodeAnalyzer
from backend.analyzers.security import SecurityAnalyzer
from backend.analyzers.unused_variables import UnusedVariablesAnalyzer

# Optional analyzers
try:
    from backend.analyzers.performance import PerformanceAnalyzer
except ImportError:
    pass

try:
    from backend.analyzers.todo_comments import TodoCommentsAnalyzer
except ImportError:
    pass

try:
    from backend.analyzers.style_checker import StyleCheckerAnalyzer
except ImportError:
    pass