#!/usr/bin/env python3

# Verification Script for Enterprise Reporting System
# Confirms all components are properly installed and configured

import sys
import os
import importlib
import subprocess
from pathlib import Path
import json
import logging

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def check_python_version():
    """Check Python version compatibility"""
    logger.info("Checking Python version...")
    
    if sys.version_info < (3, 8):
        logger.error("Python 3.8 or higher is required")
        return False
    
    logger.info(f"Python version: {sys.version}")
    return True

def check_dependencies():
    """Check if all required dependencies are installed"""
    logger.info("Checking dependencies...")
    
    required_packages = [
        'cryptography', 'requests', 'pyyaml', 'jinja2', 'click',
        'fastapi', 'uvicorn', 'pydantic',
        'sqlalchemy', 'psycopg2', 'aiopg', 'asyncpg',
        'redis', 'aioredis',
        'scikit-learn', 'numpy', 'pandas', 'scipy',
        'pyotp', 'qrcode', 'passlib', 'bcrypt',
        'bandit', 'safety', 'semgrep', 'pip-audit',
        'celery', 'pytest'
    ]
    
    missing_packages = []
    
    for package in required_packages:
        try:
            importlib.import_module(package)
            logger.debug(f"✓ {package} is installed")
        except ImportError:
            try:
                # Try alternative import names
                if package == 'psycopg2':
                    importlib.import_module('psycopg2-binary')
                    logger.debug(f"✓ psycopg2-binary is installed (alternative for psycopg2)")
                    continue
                elif package == 'pyyaml':
                    importlib.import_module('yaml')
                    logger.debug(f"✓ yaml is installed (alternative for pyyaml)")
                    continue
                elif package == 'jinja2':
                    importlib.import_module('jinja2')
                    logger.debug(f"✓ jinja2 is installed")
                    continue
                elif package == 'pydantic':
                    importlib.import_module('pydantic')
                    logger.debug(f"✓ pydantic is installed")
                    continue
                elif package == 'pyotp':
                    importlib.import_module('pyotp')
                    logger.debug(f"✓ pyotp is installed")
                    continue
                elif package == 'qrcode':
                    importlib.import_module('qrcode')
                    logger.debug(f"✓ qrcode is installed")
                    continue
                elif package == 'passlib':
                    importlib.import_module('passlib')
                    logger.debug(f"✓ passlib is installed")
                    continue
                elif package == 'bcrypt':
                    importlib.import_module('bcrypt')
                    logger.debug(f"✓ bcrypt is installed")
                    continue
                elif package == 'bandit':
                    importlib.import_module('bandit')
                    logger.debug(f"✓ bandit is installed")
                    continue
                elif package == 'safety':
                    importlib.import_module('safety')
                    logger.debug(f"✓ safety is installed")
                    continue
                elif package == 'semgrep':
                    importlib.import_module('semgrep')
                    logger.debug(f"✓ semgrep is installed")
                    continue
                elif package == 'pip-audit':
                    importlib.import_module('pip_audit')
                    logger.debug(f"✓ pip-audit is installed")
                    continue
                elif package == 'celery':
                    importlib.import_module('celery')
                    logger.debug(f"✓ celery is installed")
                    continue
                elif package == 'pytest':
                    importlib.import_module('pytest')
                    logger.debug(f"✓ pytest is installed")
                    continue
                else:
                    missing_packages.append(package)
                    logger.warning(f"✗ {package} is not installed")
            except ImportError:
                missing_packages.append(package)
                logger.warning(f"✗ {package} is not installed")
    
    if missing_packages:
        logger.error(f"Missing packages: {', '.join(missing_packages)}")
        return False
    
    logger.info("✓ All required dependencies are installed")
    return True

def check_system_tools():
    """Check if system tools are available"""
    logger.info("Checking system tools...")
    
    required_tools = ['git', 'curl', 'jq', 'docker', 'docker-compose']
    missing_tools = []
    
    for tool in required_tools:
        try:
            result = subprocess.run(['which', tool], 
                                  capture_output=True, text=True, timeout=5)
            if result.returncode == 0:
                logger.debug(f"✓ {tool} is available")
            else:
                missing_tools.append(tool)
                logger.warning(f"✗ {tool} is not available")
        except subprocess.TimeoutExpired:
            missing_tools.append(tool)
            logger.warning(f"✗ {tool} check timed out")
        except Exception as e:
            missing_tools.append(tool)
            logger.warning(f"✗ {tool} check failed: {e}")
    
    if missing_tools:
        logger.warning(f"Missing tools: {', '.join(missing_tools)}")
        # This is not fatal as some tools might be optional
        return True
    
    logger.info("✓ Required system tools are available")
    return True

def check_project_structure():
    """Check if project structure is correct"""
    logger.info("Checking project structure...")
    
    project_root = Path('/home/cbwinslow/reports/project_root')
    required_paths = [
        'src/reports',
        'docs',
        'web',
        'integrations',
        'tests',
        'config.json',
        'requirements.txt',
        'README.md'
    ]
    
    missing_paths = []
    
    for path in required_paths:
        full_path = project_root / path
        if not full_path.exists():
            missing_paths.append(path)
            logger.warning(f"✗ {path} is missing")
        else:
            logger.debug(f"✓ {path} exists")
    
    if missing_paths:
        logger.error(f"Missing project paths: {', '.join(missing_paths)}")
        return False
    
    logger.info("✓ Project structure is correct")
    return True

def check_web_interface():
    """Check if web interface files exist"""
    logger.info("Checking web interface...")
    
    web_dir = Path('/home/cbwinslow/reports/project_root/web')
    required_files = [
        'index.html',
        'css/style.css',
        'js/main.js'
    ]
    
    missing_files = []
    
    for file in required_files:
        full_path = web_dir / file
        if not full_path.exists():
            missing_files.append(file)
            logger.warning(f"✗ {file} is missing")
        else:
            logger.debug(f"✓ {file} exists")
    
    if missing_files:
        logger.error(f"Missing web interface files: {', '.join(missing_files)}")
        return False
    
    logger.info("✓ Web interface files are present")
    return True

def check_configuration():
    """Check if configuration files are present"""
    logger.info("Checking configuration files...")
    
    config_file = Path('/home/cbwinslow/reports/project_root/config.json')
    
    if not config_file.exists():
        logger.warning("✗ Main configuration file is missing")
        return False
    
    try:
        with open(config_file, 'r') as f:
            config = json.load(f)
        
        # Check required configuration sections
        required_sections = ['general', 'report_types', 'api', 'web']
        missing_sections = []
        
        for section in required_sections:
            if section not in config:
                missing_sections.append(section)
                logger.warning(f"✗ Configuration section '{section}' is missing")
            else:
                logger.debug(f"✓ Configuration section '{section}' exists")
        
        if missing_sections:
            logger.error(f"Missing configuration sections: {', '.join(missing_sections)}")
            return False
        
        logger.info("✓ Configuration file is valid")
        return True
        
    except json.JSONDecodeError as e:
        logger.error(f"✗ Configuration file is not valid JSON: {e}")
        return False
    except Exception as e:
        logger.error(f"✗ Error reading configuration file: {e}")
        return False

def check_scripts():
    """Check if essential scripts are present and executable"""
    logger.info("Checking essential scripts...")
    
    project_root = Path('/home/cbwinslow/reports/project_root')
    required_scripts = [
        'src/reports/cli.py',
        'src/reports/api_server.py',
        'src/reports/web_server.py',
        'web_server.py'
    ]
    
    missing_scripts = []
    
    for script in required_scripts:
        full_path = project_root / script
        if not full_path.exists():
            missing_scripts.append(script)
            logger.warning(f"✗ {script} is missing")
        else:
            # Check if executable
            if os.access(full_path, os.X_OK):
                logger.debug(f"✓ {script} exists and is executable")
            else:
                logger.debug(f"✓ {script} exists (not executable, which may be okay)")
    
    if missing_scripts:
        logger.error(f"Missing scripts: {', '.join(missing_scripts)}")
        return False
    
    logger.info("✓ Essential scripts are present")
    return True

def check_security_components():
    """Check if security components are present"""
    logger.info("Checking security components...")
    
    project_root = Path('/home/cbwinslow/reports/project_root')
    security_components = [
        'src/reports/security/mfa.py',
        'src/reports/security/saml.py',
        'src/reports/security/field_encryption.py',
        'src/reports/credential_manager.py',
        'src/reports/user_management.py'
    ]
    
    missing_components = []
    
    for component in security_components:
        full_path = project_root / component
        if not full_path.exists():
            missing_components.append(component)
            logger.warning(f"✗ {component} is missing")
        else:
            logger.debug(f"✓ {component} exists")
    
    if missing_components:
        logger.error(f"Missing security components: {', '.join(missing_components)}")
        return False
    
    logger.info("✓ Security components are present")
    return True

def check_monitoring_components():
    """Check if monitoring components are present"""
    logger.info("Checking monitoring components...")
    
    project_root = Path('/home/cbwinslow/reports/project_root')
    monitoring_components = [
        'src/reports/monitoring/performance_monitoring.py',
        'src/reports/caching/redis_cache.py',
        'src/reports/database/connection_pool.py',
        'integrations/prometheus_exporter.py',
        'integrations/loki_integration.py'
    ]
    
    missing_components = []
    
    for component in monitoring_components:
        full_path = project_root / component
        if not full_path.exists():
            missing_components.append(component)
            logger.warning(f"✗ {component} is missing")
        else:
            logger.debug(f"✓ {component} exists")
    
    if missing_components:
        logger.error(f"Missing monitoring components: {', '.join(missing_components)}")
        return False
    
    logger.info("✓ Monitoring components are present")
    return True

def check_documentation():
    """Check if documentation files are present"""
    logger.info("Checking documentation...")
    
    docs_dir = Path('/home/cbwinslow/reports/project_root/docs')
    required_docs = [
        'index.md',
        'installation.md',
        'configuration.md',
        'api-reference.md',
        'security.md',
        'monitoring.md',
        'field-encryption.md',
        'redis-caching-architecture.md',
        'saml-implementation.md'
    ]
    
    missing_docs = []
    
    for doc in required_docs:
        full_path = docs_dir / doc
        if not full_path.exists():
            missing_docs.append(doc)
            logger.warning(f"✗ {doc} is missing")
        else:
            logger.debug(f"✓ {doc} exists")
    
    if missing_docs:
        logger.error(f"Missing documentation files: {', '.join(missing_docs)}")
        return False
    
    logger.info("✓ Documentation files are present")
    return True

def run_verification():
    """Run complete verification of the system"""
    logger.info("=" * 60)
    logger.info(".ENTERPRISE REPORTING SYSTEM VERIFICATION")
    logger.info("=" * 60)
    
    checks = [
        ("Python Version", check_python_version),
        ("Dependencies", check_dependencies),
        ("System Tools", check_system_tools),
        ("Project Structure", check_project_structure),
        ("Web Interface", check_web_interface),
        ("Configuration", check_configuration),
        ("Scripts", check_scripts),
        ("Security Components", check_security_components),
        ("Monitoring Components", check_monitoring_components),
        ("Documentation", check_documentation)
    ]
    
    results = []
    
    for check_name, check_function in checks:
        logger.info(f"\n🔍 Running {check_name} check...")
        try:
            result = check_function()
            results.append((check_name, result))
            if result:
                logger.info(f"✅ {check_name} check PASSED")
            else:
                logger.error(f"❌ {check_name} check FAILED")
        except Exception as e:
            logger.error(f"❌ {check_name} check FAILED with exception: {e}")
            results.append((check_name, False))
    
    # Summary
    logger.info("\n" + "=" * 60)
    logger.info("VERIFICATION SUMMARY")
    logger.info("=" * 60)
    
    passed_checks = sum(1 for _, result in results if result)
    total_checks = len(results)
    
    logger.info(f"Checks Passed: {passed_checks}/{total_checks}")
    
    if passed_checks == total_checks:
        logger.info("🎉 ALL CHECKS PASSED - System is ready for use!")
        logger.info("\n🚀 NEXT STEPS:")
        logger.info("   1. Review the documentation in /home/cbwinslow/reports/project_root/docs/")
        logger.info("   2. Configure the system by editing /home/cbwinslow/reports/project_root/config.json")
        logger.info("   3. Start the services:")
        logger.info("      - API Server: python /home/cbwinslow/reports/project_root/src/reports/api_server.py")
        logger.info("      - Web Server: python /home/cbwinslow/reports/project_root/src/reports/web_server.py")
        logger.info("      - Web Interface: Navigate to http://localhost:8081/")
        logger.info("   4. Access the API at http://localhost:8080/api/v1/")
        logger.info("\n🔐 SECURITY REMINDERS:")
        logger.info("   - Change default passwords and API keys")
        logger.info("   - Configure proper SSL/TLS certificates")
        logger.info("   - Review and update security settings")
        logger.info("   - Implement proper access controls")
        return True
    else:
        logger.error("❌ SOME CHECKS FAILED - System requires attention")
        logger.info("\n🔧 TROUBLESHOOTING:")
        logger.info("   1. Check the error messages above")
        logger.info("   2. Install missing dependencies")
        logger.info("   3. Verify project structure")
        logger.info("   4. Check configuration files")
        logger.info("   5. Review documentation for setup instructions")
        return False

if __name__ == "__main__":
    success = run_verification()
    sys.exit(0 if success else 1)