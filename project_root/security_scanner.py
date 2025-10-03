#!/usr/bin/env python3
"""
Security Scanner Script for Enterprise Reporting System
Runs all security scanning tools and generates reports
"""

import subprocess
import sys
import os
import json
from datetime import datetime
from pathlib import Path

def run_security_scan():
    """Run all security scanning tools"""
    print("🚀 Starting Enterprise Reporting System Security Scan")
    print("=" * 60)
    
    # Create results directory
    results_dir = Path("security-scans")
    results_dir.mkdir(exist_ok=True)
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    
    # Initialize counters
    total_issues = 0
    critical_issues = 0
    
    # 1. Run Bandit scan
    print("\n🔍 Running Bandit Security Scan...")
    try:
        result = subprocess.run([
            "bandit", "-r", "src/", 
            "-f", "json", 
            "-o", f"security-scans/bandit-{timestamp}.json"
        ], capture_output=True, text=True, timeout=300)
        
        if result.returncode == 0:
            print("✅ Bandit scan completed successfully")
        elif result.returncode == 1:
            print("⚠️ Bandit found security issues")
            # Parse results to count issues
            try:
                with open(f"security-scans/bandit-{timestamp}.json", 'r') as f:
                    bandit_results = json.load(f)
                    issue_count = len(bandit_results.get('results', []))
                    total_issues += issue_count
                    print(f"   Found {issue_count} security issues")
            except Exception as e:
                print(f"   Error parsing Bandit results: {e}")
        else:
            print(f"❌ Bandit scan failed: {result.stderr}")
    except subprocess.TimeoutExpired:
        print("❌ Bandit scan timed out")
    except FileNotFoundError:
        print("⚠️ Bandit not installed. Install with: pip install bandit")
    except Exception as e:
        print(f"❌ Bandit scan error: {e}")
    
    # 2. Run pip-audit
    print("\n🔍 Running pip-audit Dependency Scan...")
    try:
        result = subprocess.run([
            "pip-audit", 
            "--format", "json", 
            "--output", f"security-scans/pip-audit-{timestamp}.json"
        ], capture_output=True, text=True, timeout=300)
        
        if result.returncode == 0:
            print("✅ pip-audit scan completed successfully")
        else:
            print("⚠️ pip-audit found vulnerable dependencies")
            # Parse results to count vulnerabilities
            try:
                with open(f"security-scans/pip-audit-{timestamp}.json", 'r') as f:
                    audit_results = json.load(f)
                    vuln_count = len(audit_results.get('vulnerabilities', []))
                    total_issues += vuln_count
                    print(f"   Found {vuln_count} vulnerable dependencies")
            except Exception as e:
                print(f"   Error parsing pip-audit results: {e}")
    except subprocess.TimeoutExpired:
        print("❌ pip-audit scan timed out")
    except FileNotFoundError:
        print("⚠️ pip-audit not installed. Install with: pip install pip-audit")
    except Exception as e:
        print(f"❌ pip-audit scan error: {e}")
    
    # 3. Check for basic security issues in code
    print("\n🔍 Running Basic Security Checks...")
    basic_issues = check_basic_security()
    total_issues += len(basic_issues)
    
    for issue in basic_issues:
        print(f"   ⚠️ {issue}")
    
    # Summary
    print("\n" + "=" * 60)
    print("📊 SECURITY SCAN SUMMARY")
    print("=" * 60)
    print(f"Scan completed: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"Total issues found: {total_issues}")
    
    if total_issues == 0:
        print("🎉 No security issues found! System is secure.")
        return True
    else:
        print(f"⚠️ {total_issues} security issues need attention")
        print("\n📋 Detailed reports saved to:")
        print(f"   - security-scans/bandit-{timestamp}.json")
        print(f"   - security-scans/pip-audit-{timestamp}.json")
        return False

def check_basic_security():
    """Check for basic security issues in the codebase"""
    issues = []
    
    # Check for hardcoded secrets (basic check)
    try:
        # Look for common secret patterns
        import re
        
        secret_patterns = [
            (r'["\']password["\']\s*:\s*["\'][^"\']{3,}', "Hardcoded password found"),
            (r'["\']api[_-]?key["\']\s*:\s*["\'][^"\']{10,}', "Hardcoded API key found"),
            (r'["\']secret["\']\s*:\s*["\'][^"\']{5,}', "Hardcoded secret found"),
            (r'AWS_ACCESS_KEY_ID\s*=.*', "AWS access key in environment variable"),
            (r'AWS_SECRET_ACCESS_KEY\s*=.*', "AWS secret key in environment variable"),
        ]
        
        # Search in Python files
        for py_file in Path("src").rglob("*.py"):
            try:
                with open(py_file, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                    
                    for pattern, description in secret_patterns:
                        matches = re.findall(pattern, content, re.IGNORECASE)
                        for match in matches:
                            issues.append(f"{description} in {py_file.relative_to('src')}")
            except Exception:
                continue
                
    except Exception as e:
        issues.append(f"Error in basic security check: {e}")
    
    return issues

def install_security_tools():
    """Install security scanning tools if not present"""
    tools = ["bandit", "pip-audit"]
    
    for tool in tools:
        try:
            subprocess.run([tool, "--help"], 
                         capture_output=True, check=True)
            print(f"✅ {tool} is already installed")
        except (subprocess.CalledProcessError, FileNotFoundError):
            print(f"🔧 Installing {tool}...")
            try:
                subprocess.run([sys.executable, "-m", "pip", "install", tool],
                             check=True, capture_output=True)
                print(f"✅ {tool} installed successfully")
            except subprocess.CalledProcessError:
                print(f"❌ Failed to install {tool}")

if __name__ == "__main__":
    print("Enterprise Reporting System - Security Scanner")
    print("================================================")
    
    # Check if running in a CI environment
    ci_env = os.getenv('CI', '').lower() == 'true'
    
    if not ci_env:
        # Install tools if not in CI
        install_security_tools()
    
    # Run security scan
    success = run_security_scan()
    
    # Exit with appropriate code
    sys.exit(0 if success else 1)