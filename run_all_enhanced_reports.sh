#!/bin/bash

# Enhanced Cybersecurity and Performance Reports Script with Grafana & OpenSearch Integration
# Runs all cybersecurity, performance monitoring, and integration reports

echo "Starting Enhanced Cybersecurity and Performance Reports Generation with Grafana & OpenSearch Integration..."

# Create output directory
mkdir -p /home/cbwinslow/reports/reports_output

# Run each report module in the background
echo "Running Network Traffic Analysis Report..."
python3 /home/cbwinslow/reports/src/reports/network_traffic_analysis.py > /home/cbwinslow/reports/reports_output/network_traffic_$(date +%Y%m%d_%H%M%S).json 2>/dev/null &
NT_PID=$!

echo "Running Penetration Test Results Report..."
python3 /home/cbwinslow/reports/src/reports/penetration_test_report.py > /home/cbwinslow/reports/reports_output/penetration_test_$(date +%Y%m%d_%H%M%S).json 2>/dev/null &
PT_PID=$!

echo "Running Vulnerability Scan Report..."
python3 /home/cbwinslow/reports/src/reports/vulnerability_scan_report.py > /home/cbwinslow/reports/reports_output/vulnerability_scan_$(date +%Y%m%d_%H%M%S).json 2>/dev/null &
VS_PID=$!

echo "Running Firewall and IDS Report..."
python3 /home/cbwinslow/reports/src/reports/firewall_ids_report.py > /home/cbwinslow/reports/reports_output/firewall_ids_$(date +%Y%m%d_%H%M%S).json 2>/dev/null &
FI_PID=$!

echo "Running Blue Team Activity Report..."
python3 /home/cbwinslow/reports/src/reports/blue_team_report.py > /home/cbwinslow/reports/reports_output/blue_team_$(date +%Y%m%d_%H%M%S).json 2>/dev/null &
BT_PID=$!

echo "Running Threat Intelligence Report..."
python3 /home/cbwinslow/reports/src/reports/threat_intelligence_report.py > /home/cbwinslow/reports/reports_output/threat_intel_$(date +%Y%m%d_%H%M%S).json 2>/dev/null &
TI_PID=$!

echo "Running Compliance Report..."
python3 /home/cbwinslow/reports/src/reports/compliance_report.py > /home/cbwinslow/reports/reports_output/compliance_$(date +%Y%m%d_%H%M%S).json 2>/dev/null &
C_PID=$!

echo "Running IP Logging and Network Traffic Report..."
python3 /home/cbwinslow/reports/src/reports/ip_logging_monitoring.py > /home/cbwinslow/reports/reports_output/ip_logging_$(date +%Y%m%d_%H%M%S).json 2>/dev/null &
IP_PID=$!

echo "Running User Audit and Activity Report..."
python3 /home/cbwinslow/reports/src/reports/user_audit_monitoring.py > /home/cbwinslow/reports/reports_output/user_audit_$(date +%Y%m%d_%H%M%S).json 2>/dev/null &
UA_PID=$!

echo "Running I/O Performance Report..."
python3 /home/cbwinslow/reports/src/reports/io_performance_monitoring.py > /home/cbwinslow/reports/reports_output/io_performance_$(date +%Y%m%d_%H%M%S).json 2>/dev/null &
IO_PID=$!

echo "Running GPU Monitoring Report..."
python3 /home/cbwinslow/reports/src/reports/gpu_monitoring.py > /home/cbwinslow/reports/reports_output/gpu_monitoring_$(date +%Y%m%d_%H%M%S).json 2>/dev/null &
GPU_PID=$!

echo "Running CPU and Core Performance Report..."
python3 /home/cbwinslow/reports/src/reports/cpu_monitoring.py > /home/cbwinslow/reports/reports_output/cpu_monitoring_$(date +%Y%m%d_%H%M%S).json 2>/dev/null &
CPU_PID=$!

echo "Running System Benchmarking Report..."
python3 /home/cbwinslow/reports/src/reports/system_benchmarking.py > /home/cbwinslow/reports/reports_output/system_benchmarking_$(date +%Y%m%d_%H%M%S).json 2>/dev/null &
SB_PID=$!

echo "Running Interactive Charting Report..."
python3 /home/cbwinslow/reports/src/reports/interactive_charting.py > /home/cbwinslow/reports/reports_output/interactive_charting_$(date +%Y%m%d_%H%M%S).json 2>/dev/null &
IC_PID=$!

echo "Running Process Monitoring Report..."
python3 /home/cbwinslow/reports/src/reports/process_monitoring.py > /home/cbwinslow/reports/reports_output/process_monitoring_$(date +%Y%m%d_%H%M%S).json 2>/dev/null &
PM_PID=$!

echo "Running Storage Monitoring Report..."
python3 /home/cbwinslow/reports/src/reports/storage_monitoring.py > /home/cbwinslow/reports/reports_output/storage_monitoring_$(date +%Y%m%d_%H%M%S).json 2>/dev/null &
SM_PID=$!

echo "Running Grafana Integration Report..."
python3 /home/cbwinslow/reports/src/reports/grafana_integration.py > /home/cbwinslow/reports/reports_output/grafana_integration_$(date +%Y%m%d_%H%M%S).json 2>/dev/null &
GI_PID=$!

echo "Running OpenSearch Integration Report..."
python3 /home/cbwinslow/reports/src/reports/opensearch_integration.py > /home/cbwinslow/reports/reports_output/opensearch_integration_$(date +%Y%m%d_%H%M%S).json 2>/dev/null &
OI_PID=$!

# Wait for all processes to complete
wait $NT_PID
wait $PT_PID
wait $VS_PID
wait $FI_PID
wait $BT_PID
wait $TI_PID
wait $C_PID
wait $IP_PID
wait $UA_PID
wait $IO_PID
wait $GPU_PID
wait $CPU_PID
wait $SB_PID
wait $IC_PID
wait $PM_PID
wait $SM_PID
wait $GI_PID
wait $OI_PID

echo "Enhanced cybersecurity, performance, and integration reports generation completed."
echo "Output files saved to /home/cbwinslow/reports/reports_output/"