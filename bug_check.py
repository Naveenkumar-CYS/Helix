"""
Comprehensive Bug Check Script
Tests all modules, imports, and basic functionality
"""

import sys
import importlib
from pathlib import Path

def check_module(module_name):
    """Check if a module can be imported without errors."""
    try:
        importlib.import_module(module_name)
        return True, "OK"
    except Exception as e:
        return False, str(e)

def main():
    print("=" * 70)
    print("COMPREHENSIVE BUG CHECK - AI HONEYPOT")
    print("=" * 70)
    print()
    
    # List of all modules to check
    modules = [
        "analyzer",
        "attack_predictor",
        "mitre_mapper",
        "forensic_timeline",
        "threat_sharing",
        "playbook_generator",
        "canary_analytics",
        "logger",
        "behavioral_analyzer",
        "deception_engine",
        "correlation_engine",
        "threat_intel",
        "content_generator",
        "fingerprinting",
        "alerts",
        "ml_classifier",
        "llm_engine",
        "external_threat_intel",
        "counter_intelligence",
        "export_engine",
        "adaptive_deception",
    ]
    
    results = []
    
    print("1. MODULE IMPORT CHECKS")
    print("-" * 70)
    
    for module in modules:
        success, message = check_module(module)
        status = "PASS" if success else "FAIL"
        results.append((module, success))
        
        if success:
            print(f"  [{status}] {module:30} - Imported successfully")
        else:
            print(f"  [{status}] {module:30} - ERROR: {message[:40]}")
    
    print()
    
    # Summary
    passed = sum(1 for _, success in results if success)
    total = len(results)
    
    print("=" * 70)
    print("SUMMARY")
    print("=" * 70)
    print(f"Modules Checked: {total}")
    print(f"Passed: {passed}")
    print(f"Failed: {total - passed}")
    print(f"Success Rate: {(passed/total)*100:.1f}%")
    print()
    
    if passed == total:
        print("SUCCESS: All modules passed import checks!")
        return 0
    else:
        print("WARNING: Some modules failed. Check errors above.")
        return 1

if __name__ == "__main__":
    sys.exit(main())
