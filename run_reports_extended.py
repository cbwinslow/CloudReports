#!/usr/bin/env python3
"""
Enterprise Reporting System - Extended with Cybersecurity Reports
Main entry point that ties together all report modules
"""

import argparse
import json
import sys
from pathlib import Path
from datetime import datetime

# Add the src directory to the path so we can import our modules
sys.path.append(str(Path(__file__).parent / "src"))

# Import all cybersecurity report modules
from reports.network_traffic_analysis import run_network_traffic_analysis
from reports.penetration_test_report import run_penetration_test_reporting
from reports.vulnerability_scan_report import run_vulnerability_scan_reporting
from reports.firewall_ids_report import run_firewall_ids_reporting
from reports.blue_team_report import run_blue_team_reporting
from reports.threat_intelligence_report import run_threat_intelligence_reporting
from reports.compliance_report import run_compliance_reporting

# Import performance and system monitoring modules
from reports.ip_logging_monitoring import run_ip_logging_monitoring
from reports.user_audit_monitoring import run_user_audit_monitoring
from reports.io_performance_monitoring import run_io_performance_monitoring
from reports.gpu_monitoring import run_gpu_monitoring
from reports.cpu_monitoring import run_cpu_monitoring
from reports.system_benchmarking import run_system_benchmarking
from reports.interactive_charting import run_charting_service
from reports.process_monitoring import run_process_monitoring
from reports.storage_monitoring import run_storage_monitoring
from reports.grafana_integration import run_grafana_integration
from reports.opensearch_integration import run_opensearch_integration


def run_all_reports():
    """Run all available reports and save them to files"""
    print("Running all enterprise reports...")
    
    # Define reports to run with their output filenames
    reports_to_run = [
        ("Network Traffic Analysis Report", "network_traffic_analysis", run_network_traffic_analysis),
        ("Penetration Test Report", "penetration_test_results", run_penetration_test_reporting),
        ("Vulnerability Scan Report", "vulnerability_scan_results", run_vulnerability_scan_reporting),
        ("Firewall and IDS Report", "firewall_ids_activity", run_firewall_ids_reporting),
        ("Blue Team Activity Report", "blue_team_activities", run_blue_team_reporting),
        ("Threat Intelligence Report", "threat_intelligence", run_threat_intelligence_reporting),
        ("Security Compliance Report", "security_compliance", run_compliance_reporting),
        ("IP Logging and Network Traffic Report", "ip_logging", run_ip_logging_monitoring),
        ("User Audit and Activity Report", "user_audit", run_user_audit_monitoring),
        ("I/O Performance Report", "io_performance", run_io_performance_monitoring),
        ("GPU Monitoring Report", "gpu_monitoring", run_gpu_monitoring),
        ("CPU and Core Performance Report", "cpu_monitoring", run_cpu_monitoring),
        ("System Benchmarking Report", "system_benchmarking", run_system_benchmarking),
        ("Interactive Charting Report", "interactive_charting", run_charting_service),
        ("Process Monitoring Report", "process_monitoring", run_process_monitoring),
        ("Storage Monitoring Report", "storage_monitoring", run_storage_monitoring),
        ("Grafana Integration Report", "grafana_integration", run_grafana_integration),
        ("OpenSearch Integration Report", "opensearch_integration", run_opensearch_integration),
    ]
    
    results = {}
    
    for report_name, filename, report_function in reports_to_run:
        try:
            print(f"Generating {report_name}...")
            report_data = report_function()
            
            # Save report to JSON file
            output_file = f"reports_output/{filename}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            Path("reports_output").mkdir(exist_ok=True)
            
            with open(output_file, 'w') as f:
                json.dump(report_data, f, indent=2, default=str)
            
            results[filename] = {
                "status": "success",
                "output_file": output_file,
                "timestamp": datetime.now().isoformat()
            }
            
            print(f"  ✓ Saved to {output_file}")
            
        except Exception as e:
            print(f"  ✗ Failed to generate {report_name}: {str(e)}")
            results[filename] = {
                "status": "error",
                "error": str(e),
                "timestamp": datetime.now().isoformat()
            }
    
    # Save summary report
    summary_file = f"reports_output/summary_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(summary_file, 'w') as f:
        json.dump({
            "summary": results,
            "generated_at": datetime.now().isoformat(),
            "total_reports": len(reports_to_run),
            "successful_reports": len([r for r in results.values() if r["status"] == "success"])
        }, f, indent=2)
    
    print(f"\nSummary saved to {summary_file}")
    return results


def run_single_report(report_type):
    """Run a specific report type"""
    report_functions = {
        "network_traffic": run_network_traffic_analysis,
        "penetration_test": run_penetration_test_reporting,
        "vulnerability_scan": run_vulnerability_scan_reporting,
        "firewall_ids": run_firewall_ids_reporting,
        "blue_team": run_blue_team_reporting,
        "threat_intelligence": run_threat_intelligence_reporting,
        "compliance": run_compliance_reporting,
        "ip_logging": run_ip_logging_monitoring,
        "user_audit": run_user_audit_monitoring,
        "io_performance": run_io_performance_monitoring,
        "gpu_monitoring": run_gpu_monitoring,
        "cpu_monitoring": run_cpu_monitoring,
        "system_benchmarking": run_system_benchmarking,
        "interactive_charting": run_charting_service,
        "process_monitoring": run_process_monitoring,
        "storage_monitoring": run_storage_monitoring,
        "grafana_integration": run_grafana_integration,
        "opensearch_integration": run_opensearch_integration
    }
    
    if report_type not in report_functions:
        print(f"Unknown report type: {report_type}")
        print(f"Available report types: {', '.join(report_functions.keys())}")
        return None
    
    try:
        print(f"Generating {report_type.replace('_', ' ').title()} Report...")
        report_data = report_functions[report_type]()
        
        # Save report to JSON file
        output_file = f"reports_output/{report_type}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        Path("reports_output").mkdir(exist_ok=True)
        
        with open(output_file, 'w') as f:
            json.dump(report_data, f, indent=2, default=str)
        
        print(f"Report saved to {output_file}")
        return report_data
        
    except Exception as e:
        print(f"Failed to generate {report_type} report: {str(e)}")
        return None


def main():
    parser = argparse.ArgumentParser(description="Enterprise Reporting System with Cybersecurity Extensions")
    parser.add_argument(
        "action", 
        choices=["run-all", "run-single", "list-types"],
        help="Action to perform"
    )
    parser.add_argument(
        "--type",
        help="Specific report type to run (for run-single action)",
        choices=[
            "network_traffic", "penetration_test", "vulnerability_scan",
            "firewall_ids", "blue_team", "threat_intelligence", "compliance",
            "ip_logging", "user_audit", "io_performance",
            "gpu_monitoring", "cpu_monitoring", "system_benchmarking", "interactive_charting",
            "process_monitoring", "storage_monitoring", "grafana_integration", "opensearch_integration"
        ]
    )
    parser.add_argument(
        "--config",
        help="Configuration file path",
        default="config.json"
    )
    
    args = parser.parse_args()
    
    if args.action == "list-types":
        print("Available cybersecurity and performance report types:")
        report_functions = {
            "network_traffic": "Network Traffic Analysis Report",
            "penetration_test": "Penetration Test Results Report", 
            "vulnerability_scan": "Vulnerability Scan Results Report",
            "firewall_ids": "Firewall and IDS Activity Report",
            "blue_team": "Blue Team Activity Report",
            "threat_intelligence": "Threat Intelligence Report",
            "compliance": "Security Compliance Report",
            "ip_logging": "IP Address Logging and Network Traffic Monitoring",
            "user_audit": "User Audit and Activity Monitoring",
            "io_performance": "I/O Throughput and Performance Monitoring",
            "gpu_monitoring": "GPU Performance Monitoring",
            "cpu_monitoring": "CPU and Core Performance Monitoring",
            "system_benchmarking": "System Benchmarking Suite",
            "interactive_charting": "Interactive Charting with Date Range Selection",
            "process_monitoring": "Process Monitoring and Performance Tracking",
            "storage_monitoring": "Storage and Filesystem Monitoring",
            "grafana_integration": "Grafana Integration and Dashboard Management",
            "opensearch_integration": "OpenSearch Integration and Log Aggregation"
        }
        
        for report_type, description in report_functions.items():
            print(f"  {report_type}: {description}")
    
    elif args.action == "run-all":
        run_all_reports()
        
    elif args.action == "run-single":
        if not args.type:
            print("Please specify a report type using --type")
            return 1
        
        run_single_report(args.type)


if __name__ == "__main__":
    main()