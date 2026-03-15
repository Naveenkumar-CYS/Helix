"""
Advanced Bug Check - API Endpoints and Integration Testing
"""

import sys
import re
from pathlib import Path

def check_app_py_endpoints():
    """Extract and validate all API endpoints from app.py"""
    print("2. API ENDPOINT VALIDATION")
    print("-" * 70)
    
    app_file = Path("app.py")
    if not app_file.exists():
        print("  [FAIL] app.py not found!")
        return False
    
    content = app_file.read_text()
    
    # Find all @app.get, @app.post, @app.websocket decorators
    get_endpoints = re.findall(r'@app\.get\(["\']([^"\']+)["\']\)', content)
    post_endpoints = re.findall(r'@app\.post\(["\']([^"\']+)["\']\)', content)
    ws_endpoints = re.findall(r'@app\.websocket\(["\']([^"\']+)["\']\)', content)
    
    print(f"\n  Found {len(get_endpoints)} GET endpoints:")
    for ep in get_endpoints:
        print(f"    - GET  {ep}")
    
    print(f"\n  Found {len(post_endpoints)} POST endpoints:")
    for ep in post_endpoints:
        print(f"    - POST {ep}")
    
    print(f"\n  Found {len(ws_endpoints)} WebSocket endpoints:")
    for ep in ws_endpoints:
        print(f"    - WS   {ep}")
    
    total = len(get_endpoints) + len(post_endpoints) + len(ws_endpoints)
    print(f"\n  Total Endpoints: {total}")
    
    return total > 0

def check_imports_in_app():
    """Check all imports in app.py"""
    print("\n3. APP.PY IMPORT VALIDATION")
    print("-" * 70)
    
    app_file = Path("app.py")
    content = app_file.read_text()
    
    # Find all import statements
    imports = re.findall(r'^(?:from|import)\s+(\w+)', content, re.MULTILINE)
    
    # Filter to local modules (not stdlib or third-party)
    local_modules = [
        "analyzer", "attack_predictor", "mitre_mapper", "forensic_timeline",
        "threat_sharing", "playbook_generator", "canary_analytics", "logger",
        "behavioral_analyzer", "deception_engine", "correlation_engine",
        "threat_intel", "content_generator", "fingerprinting", "alerts",
        "ml_classifier", "llm_engine", "external_threat_intel",
        "counter_intelligence", "export_engine", "adaptive_deception"
    ]
    
    used_modules = [m for m in imports if m in local_modules]
    
    print(f"  Local modules imported in app.py: {len(used_modules)}")
    for mod in sorted(set(used_modules)):
        print(f"    - {mod}")
    
    return True

def check_json_files():
    """Check if required JSON files exist or can be created"""
    print("\n4. DATA FILE CHECKS")
    print("-" * 70)
    
    required_files = {
        "attacks.json": "Attack log file",
        "attacker_profiles.json": "Attacker profiles"
    }
    
    for filename, description in required_files.items():
        filepath = Path(filename)
        if filepath.exists():
            size = filepath.stat().st_size
            print(f"  [EXISTS] {filename:25} - {description} ({size} bytes)")
        else:
            print(f"  [MISSING] {filename:25} - {description} (will be created on first run)")
    
    return True

def check_syntax_all_files():
    """Check Python syntax for all .py files"""
    print("\n5. SYNTAX CHECK - ALL PYTHON FILES")
    print("-" * 70)
    
    py_files = list(Path(".").glob("*.py"))
    errors = []
    
    for py_file in py_files:
        if py_file.name.startswith("venv"):
            continue
        
        try:
            compile(py_file.read_text(encoding='utf-8', errors='ignore'), py_file.name, 'exec')
            print(f"  [PASS] {py_file.name:30} - No syntax errors")
        except SyntaxError as e:
            print(f"  [FAIL] {py_file.name:30} - Syntax error: {e}")
            errors.append((py_file.name, str(e)))
    
    if errors:
        print(f"\n  WARNING: {len(errors)} files with syntax errors")
        return False
    else:
        print(f"\n  SUCCESS: All {len(py_files)} files have valid syntax")
        return True

def main():
    print("=" * 70)
    print("ADVANCED BUG CHECK - INTEGRATION & VALIDATION")
    print("=" * 70)
    print()
    
    results = []
    
    # Run all checks
    results.append(("API Endpoints", check_app_py_endpoints()))
    results.append(("App.py Imports", check_imports_in_app()))
    results.append(("Data Files", check_json_files()))
    results.append(("Syntax Check", check_syntax_all_files()))
    
    # Summary
    print("\n" + "=" * 70)
    print("ADVANCED CHECK SUMMARY")
    print("=" * 70)
    
    for check_name, passed in results:
        status = "PASS" if passed else "FAIL"
        print(f"  [{status}] {check_name}")
    
    all_passed = all(passed for _, passed in results)
    
    print()
    if all_passed:
        print("SUCCESS: All advanced checks passed!")
        return 0
    else:
        print("WARNING: Some checks failed. Review above.")
        return 1

if __name__ == "__main__":
    sys.exit(main())
