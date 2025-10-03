#!/usr/bin/env python3
"""
Final Integration Test
Verifies that all enhanced modules work correctly with the API server
"""

import json
import sys
import os
sys.path.append('/home/cbwinslow/reports')

# Import all the new modules
from src.reports.process_monitoring import run_process_monitoring
from src.reports.storage_monitoring import run_storage_monitoring
from src.reports.grafana_integration import run_grafana_integration
from src.reports.opensearch_integration import run_opensearch_integration

def test_all_modules():
    """Test all enhanced modules to ensure they work correctly"""
    print("=== Final Integration Test ===")
    print("Testing all enhanced modules...")
    
    # Test process monitoring
    print("\n1. Testing Process Monitoring Module...")
    try:
        result = run_process_monitoring()
        print("   ✓ Process monitoring works correctly")
        assert 'process_summary_report' in result
        assert 'process_performance_report' in result
        print("   ✓ Process monitoring returns expected data structure")
    except Exception as e:
        print(f"   ✗ Process monitoring failed: {e}")
        return False
    
    # Test storage monitoring
    print("\n2. Testing Storage Monitoring Module...")
    try:
        result = run_storage_monitoring()
        print("   ✓ Storage monitoring works correctly")
        assert 'storage_summary_report' in result
        assert 'storage_performance_report' in result
        print("   ✓ Storage monitoring returns expected data structure")
    except Exception as e:
        print(f"   ✗ Storage monitoring failed: {e}")
        return False
    
    # Test Grafana integration
    print("\n3. Testing Grafana Integration Module...")
    try:
        result = run_grafana_integration()
        print("   ✓ Grafana integration works correctly")
        assert 'grafana_integration_report' in result
        print("   ✓ Grafana integration returns expected data structure")
    except Exception as e:
        print(f"   ✗ Grafana integration failed: {e}")
        return False
    
    # Test OpenSearch integration
    print("\n4. Testing OpenSearch Integration Module...")
    try:
        result = run_opensearch_integration()
        print("   ✓ OpenSearch integration works correctly")
        assert 'opensearch_integration_report' in result
        print("   ✓ OpenSearch integration returns expected data structure")
    except Exception as e:
        print(f"   ✗ OpenSearch integration failed: {e}")
        return False
    
    print("\n=== All Tests Passed Successfully ===")
    print("All enhanced modules are working correctly!")
    return True

if __name__ == "__main__":
    success = test_all_modules()
    sys.exit(0 if success else 1)