from fastapi import FastAPI, File, UploadFile, HTTPException
from fastapi.middleware.cors import CORSMiddleware
import os
import sys
import json
import argparse
import importlib
from typing import List, Dict, Any

# Add project root to path for imports
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from backend.analyzer import Issue  # Assuming your Issue class with to_dict() method

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

def load_analyzer(analyzer_name: str, file_path: str):
    """Dynamically load analyzer class by name."""
    try:
        module = importlib.import_module(f"backend.analyzers.{analyzer_name}")
        class_name = ''.join(word.capitalize() for word in analyzer_name.split('_')) + 'Analyzer'
        analyzer_class = getattr(module, class_name)
        return analyzer_class(file_path)
    except (ImportError, AttributeError) as e:
        print(f"Warning: Could not load analyzer '{analyzer_name}': {e}")
        return None

def get_default_analyzers(file_path: str):
    """Return list of instantiated default + optional analyzers."""
    analyzer_names = [
        "unused_imports",
        "dead_code",
        "security",
        "unused_variables",
    ]

    optional_analyzers = [
        "todo_comments",
        "performance",
        "style_checker",
    ]

    analyzers = []
    for name in analyzer_names + optional_analyzers:
        analyzer = load_analyzer(name, file_path)
        if analyzer:
            analyzers.append(analyzer)
    return analyzers

def analyze_code(code: str, file_path: str) -> List[Dict[str, Any]]:
    """Analyze code string with all analyzers and return combined issues."""
    issues = []
    analyzers = get_default_analyzers(file_path)

    for analyzer in analyzers:
        analyzer.issues.clear()  # Clear previous issues
        analyzer.analyze(code)
        for issue in analyzer.issues:
            issues.append({
                "line": issue.line,
                "column": getattr(issue, "column", 0),
                "issue_type": getattr(issue, "issue_type", "unknown"),
                "message": issue.message,
                "severity": getattr(issue, "severity", "unknown"),
                "analyzer": analyzer.__class__.__name__
            })

    return issues

@app.post("/analyze/")
async def analyze_file_endpoint(file: UploadFile = File(...)):
    """Analyze uploaded Python file, return issues."""
    if not file.filename.endswith(".py"):
        raise HTTPException(status_code=400, detail="Only Python (.py) files are supported.")

    content = await file.read()
    code = content.decode("utf-8")
    file_path = file.filename

    issues = analyze_code(code, file_path)

    return {
        "filename": file_path,
        "analysis": issues
    }


# CLI support: analyze file or directory path
def analyze_file_path(file_path: str, analyzers: List[str] = None) -> List[Dict[str, Any]]:
    """Analyze Python file on disk, given file path."""
    if not os.path.isfile(file_path) or not file_path.endswith(".py"):
        return []

    with open(file_path, "r", encoding="utf-8") as f:
        code = f.read()

    if analyzers:
        # if specific analyzer names provided
        analyzer_objs = []
        for name in analyzers:
            analyzer = load_analyzer(name, file_path)
            if analyzer:
                analyzer_objs.append(analyzer)
    else:
        analyzer_objs = get_default_analyzers(file_path)

    issues = []
    for analyzer in analyzer_objs:
        analyzer.issues.clear()
        analyzer.analyze(code)
        for issue in analyzer.issues:
            issues.append(issue.to_dict())

    return issues

def analyze_directory(directory: str, analyzers: List[str] = None) -> Dict[str, List[Dict[str, Any]]]:
    """Analyze all Python files in directory recursively."""
    results = {}

    for root, _, files in os.walk(directory):
        for file in files:
            if file.endswith(".py"):
                path = os.path.join(root, file)
                file_issues = analyze_file_path(path, analyzers)
                if file_issues:
                    results[path] = file_issues
    return results

def main():
    parser = argparse.ArgumentParser(description="Static code analyzer")
    parser.add_argument("path", help="File or directory path to analyze")
    parser.add_argument("--analyzers", nargs="+", default=None, help="Analyzers to use (optional)")
    parser.add_argument("--output", help="Output JSON file path")
    args = parser.parse_args()

    if os.path.isfile(args.path):
        results = {args.path: analyze_file_path(args.path, args.analyzers)}
    else:
        results = analyze_directory(args.path, args.analyzers)

    # Summary print
    total_issues = sum(len(issues) for issues in results.values())
    print(f"\nTotal issues found: {total_issues}")

    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            json.dump(results, f, indent=2)
        print(f"Results saved to {args.output}")
    else:
        for file_path, issues in results.items():
            print(f"\nFile: {file_path}")
            for issue in issues:
                print(f"  Line {issue['line']}, Col {issue.get('column', 0)}: [{issue.get('severity', 'unknown')}] {issue.get('issue_type', 'unknown')} - {issue.get('message')}")

if __name__ == "__main__":
    main()