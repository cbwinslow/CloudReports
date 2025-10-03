"""
Test file for Enterprise Reporting System package
"""

def test_import():
    """Test that the main package can be imported"""
    try:
        import reports
        print(f"✅ Reports package imported successfully. Version: {reports.__version__}")
        return True
    except ImportError as e:
        print(f"❌ Failed to import reports package: {e}")
        return False

def test_cli():
    """Test that CLI is available"""
    import subprocess
    try:
        result = subprocess.run(['python', '-m', 'reports.cli', '--help'], 
                              capture_output=True, text=True, timeout=10)
        if result.returncode == 0:
            print("✅ CLI module works correctly")
            return True
        else:
            print(f"❌ CLI module failed: {result.stderr}")
            return False
    except subprocess.TimeoutExpired:
        print("❌ CLI test timed out")
        return False
    except Exception as e:
        print(f"❌ CLI test failed: {e}")
        return False

if __name__ == "__main__":
    print("Testing Enterprise Reporting System package...")
    print()
    
    success = True
    success &= test_import()
    success &= test_cli()
    
    print()
    if success:
        print("🎉 All tests passed!")
    else:
        print("💥 Some tests failed!")
        exit(1)