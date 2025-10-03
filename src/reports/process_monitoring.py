#!/usr/bin/env python3
"""
Process Monitoring Module
Provides comprehensive tracking of system processes, resource usage, and performance
"""

import json
import datetime
import psutil
import os
from typing import Dict, List, Optional
from dataclasses import dataclass
from collections import defaultdict
import time
import threading


@dataclass
class ProcessInfo:
    """Data structure for process information"""
    pid: int
    name: str
    status: str
    username: str
    create_time: datetime.datetime
    cpu_percent: float
    memory_percent: float
    memory_rss: int
    memory_vms: int
    num_threads: int
    num_fds: int
    connections_count: int
    io_read_bytes: int
    io_write_bytes: int
    cmd_line: List[str]


@dataclass
class ProcessPerformanceRecord:
    """Data structure for process performance records"""
    timestamp: datetime.datetime
    pid: int
    name: str
    cpu_percent: float
    memory_percent: float
    memory_rss: int
    num_threads: int
    io_read_bytes: int
    io_write_bytes: int


class ProcessMonitor:
    """Monitors and tracks system processes and their performance"""
    
    def __init__(self, config: Dict):
        self.config = config
        self.performance_history = []
        self.monitoring = False
        self.monitor_thread = None
        self.top_processes_count = config.get('top_processes_count', 20)
        
    def get_process_info(self) -> List[ProcessInfo]:
        """Get information about all running processes"""
        processes = []
        
        for proc in psutil.process_iter(['pid', 'name', 'status', 'username', 'create_time', 
                                       'cpu_percent', 'memory_percent', 'memory_info', 
                                       'num_threads', 'num_fds', 'cmdline', 'io_counters']):
            try:
                # Get process information
                io_counters = proc.info['io_counters']
                if io_counters:
                    read_bytes = io_counters.read_bytes
                    write_bytes = io_counters.write_bytes
                else:
                    read_bytes = 0
                    write_bytes = 0
                
                # Note: Cannot access 'connections' directly in psutil.process_iter
                # We'll skip connection counting for now to avoid the error
                connections_count = 0
                
                process_info = ProcessInfo(
                    pid=proc.info['pid'],
                    name=proc.info['name'] or "Unknown",
                    status=proc.info['status'] or "unknown",
                    username=proc.info['username'] or "unknown",
                    create_time=datetime.datetime.fromtimestamp(proc.info['create_time']) if proc.info['create_time'] else datetime.datetime.now(),
                    cpu_percent=proc.info['cpu_percent'] or 0.0,
                    memory_percent=proc.info['memory_percent'] or 0.0,
                    memory_rss=proc.info['memory_info'].rss if proc.info['memory_info'] else 0,
                    memory_vms=proc.info['memory_info'].vms if proc.info['memory_info'] else 0,
                    num_threads=proc.info['num_threads'] or 0,
                    num_fds=proc.info['num_fds'] or 0,
                    connections_count=connections_count,
                    io_read_bytes=read_bytes,
                    io_write_bytes=write_bytes,
                    cmd_line=str(proc.info['cmdline']) if proc.info['cmdline'] else ""
                )
                
                processes.append(process_info)
                
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                # Skip processes that are no longer available or can't be accessed
                continue
        
        return processes
    
    def get_top_processes(self, process_info_list: List[ProcessInfo], count: int = 10) -> List[ProcessInfo]:
        """Get top processes by various metrics"""
        # Sort by CPU usage
        top_cpu = sorted(process_info_list, key=lambda p: p.cpu_percent, reverse=True)[:count]
        
        # Sort by memory usage
        top_memory = sorted(process_info_list, key=lambda p: p.memory_rss, reverse=True)[:count]
        
        # Sort by I/O activity
        top_io = sorted(process_info_list, key=lambda p: p.io_read_bytes + p.io_write_bytes, reverse=True)[:count]
        
        # Combine and deduplicate
        # We can't use set() with dataclasses because they're not hashable
        # Instead, we'll deduplicate by PID
        seen_pids = set()
        top_processes = []
        for process in (top_cpu + top_memory + top_io):
            if process.pid not in seen_pids:
                seen_pids.add(process.pid)
                top_processes.append(process)
        return top_processes[:count]  # Return only the requested count
    
    def get_process_performance(self) -> List[ProcessPerformanceRecord]:
        """Get performance metrics for processes"""
        records = []
        timestamp = datetime.datetime.now()
        
        for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent', 'memory_info', 'num_threads', 'io_counters']):
            try:
                io_counters = proc.info['io_counters']
                if io_counters:
                    read_bytes = io_counters.read_bytes
                    write_bytes = io_counters.write_bytes
                else:
                    read_bytes = 0
                    write_bytes = 0
                
                record = ProcessPerformanceRecord(
                    timestamp=timestamp,
                    pid=proc.info['pid'],
                    name=proc.info['name'] or "Unknown",
                    cpu_percent=proc.info['cpu_percent'] or 0.0,
                    memory_percent=proc.info['memory_percent'] or 0.0,
                    memory_rss=proc.info['memory_info'].rss if proc.info['memory_info'] else 0,
                    num_threads=proc.info['num_threads'] or 0,
                    io_read_bytes=read_bytes,
                    io_write_bytes=write_bytes
                )
                
                records.append(record)
                
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue
        
        return records
    
    def start_monitoring(self):
        """Start continuous process monitoring in a background thread"""
        if self.monitoring:
            return
        
        self.monitoring = True
        self.monitor_thread = threading.Thread(target=self._monitor_loop)
        self.monitor_thread.daemon = True
        self.monitor_thread.start()
    
    def stop_monitoring(self):
        """Stop continuous process monitoring"""
        self.monitoring = False
        if self.monitor_thread:
            self.monitor_thread.join()
    
    def _monitor_loop(self):
        """Internal monitoring loop"""
        while self.monitoring:
            try:
                # Collect process performance data
                records = self.get_process_performance()
                
                # Store in history
                self.performance_history.extend(records)
                
                # Apply retention policy
                self._apply_retention_policy()
                
                # Wait before next collection
                time.sleep(self.config.get('monitor_interval', 5))
                
            except Exception as e:
                print(f"Error in process monitoring loop: {e}")
                time.sleep(self.config.get('monitor_interval', 5))
    
    def _apply_retention_policy(self):
        """Apply retention policy to limit history size"""
        retention_hours = self.config.get('retention_hours', 24)
        cutoff_time = datetime.datetime.now() - datetime.timedelta(hours=retention_hours)
        
        # Filter out old records
        self.performance_history = [
            record for record in self.performance_history 
            if record.timestamp >= cutoff_time
        ]
    
    def generate_process_summary_report(self) -> Dict:
        """Generate a summary report of system processes"""
        all_processes = self.get_process_info()
        
        if not all_processes:
            return {"message": "No processes found"}
        
        # Calculate various metrics
        total_processes = len(all_processes)
        running_processes = len([p for p in all_processes if p.status.lower() == 'running'])
        sleeping_processes = len([p for p in all_processes if p.status.lower() == 'sleeping'])
        zombie_processes = len([p for p in all_processes if p.status.lower() == 'zombie'])
        
        # Calculate memory and CPU usage totals
        total_cpu_percent = sum(p.cpu_percent for p in all_processes)
        total_memory_rss = sum(p.memory_rss for p in all_processes)
        
        # Top processes by various metrics
        top_processes = self.get_top_processes(all_processes, self.top_processes_count)
        
        return {
            'report_type': 'Process Summary Report',
            'generated_at': datetime.datetime.now().isoformat(),
            'summary': {
                'total_processes': total_processes,
                'running_processes': running_processes,
                'sleeping_processes': sleeping_processes,
                'zombie_processes': zombie_processes,
                'total_cpu_percent': round(total_cpu_percent, 2),
                'total_memory_rss_bytes': total_memory_rss,
                'unique_users': len(set(p.username for p in all_processes))
            },
            'top_processes': [
                {
                    'pid': proc.pid,
                    'name': proc.name,
                    'username': proc.username,
                    'status': proc.status,
                    'cpu_percent': proc.cpu_percent,
                    'memory_rss_mb': round(proc.memory_rss / (1024*1024), 2),
                    'num_threads': proc.num_threads,
                    'io_bytes_total': proc.io_read_bytes + proc.io_write_bytes
                }
                for proc in top_processes
            ],
            'process_count_by_user': {
                user: len([p for p in all_processes if p.username == user])
                for user in set(p.username for p in all_processes)
            },
            'process_count_by_status': {
                status: len([p for p in all_processes if p.status.lower() == status.lower()])
                for status in set(p.status.lower() for p in all_processes)
            }
        }
    
    def generate_process_performance_report(self) -> Dict:
        """Generate a report on process performance over time"""
        if not self.performance_history:
            # Get a snapshot if no history
            records = self.get_process_performance()
            self.performance_history.extend(records)
        
        # Aggregate data by process name
        process_aggregates = defaultdict(lambda: {
            'cpu_percent_total': 0,
            'memory_percent_total': 0,
            'memory_rss_total': 0,
            'io_read_bytes_total': 0,
            'io_write_bytes_total': 0,
            'sample_count': 0,
            'max_cpu_percent': 0,
            'max_memory_rss': 0,
            'max_io_bytes': 0
        })
        
        for record in self.performance_history:
            proc_name = record.name
            process_aggregates[proc_name]['cpu_percent_total'] += record.cpu_percent
            process_aggregates[proc_name]['memory_percent_total'] += record.memory_percent
            process_aggregates[proc_name]['memory_rss_total'] += record.memory_rss
            process_aggregates[proc_name]['io_read_bytes_total'] += record.io_read_bytes
            process_aggregates[proc_name]['io_write_bytes_total'] += record.io_write_bytes
            process_aggregates[proc_name]['sample_count'] += 1
            
            # Track maximums
            process_aggregates[proc_name]['max_cpu_percent'] = max(
                process_aggregates[proc_name]['max_cpu_percent'],
                record.cpu_percent
            )
            process_aggregates[proc_name]['max_memory_rss'] = max(
                process_aggregates[proc_name]['max_memory_rss'],
                record.memory_rss
            )
            process_aggregates[proc_name]['max_io_bytes'] = max(
                process_aggregates[proc_name]['max_io_bytes'],
                record.io_read_bytes + record.io_write_bytes
            )
        
        # Calculate time range
        if self.performance_history:
            timestamps = [r.timestamp for r in self.performance_history]
            time_range = {
                'start': min(timestamps).isoformat(),
                'end': max(timestamps).isoformat()
            }
        else:
            time_range = {'start': None, 'end': None}
        
        return {
            'report_type': 'Process Performance Report',
            'generated_at': datetime.datetime.now().isoformat(),
            'time_range': time_range,
            'summary': {
                'total_samples': len(self.performance_history),
                'unique_processes_tracked': len(process_aggregates)
            },
            'process_performance_breakdown': {
                proc_name: {
                    'avg_cpu_percent': round(data['cpu_percent_total'] / data['sample_count'], 2) if data['sample_count'] > 0 else 0,
                    'avg_memory_percent': round(data['memory_percent_total'] / data['sample_count'], 2) if data['sample_count'] > 0 else 0,
                    'avg_memory_rss_mb': round((data['memory_rss_total'] / data['sample_count']) / (1024*1024), 2) if data['sample_count'] > 0 else 0,
                    'total_io_read_mb': round(data['io_read_bytes_total'] / (1024*1024), 2),
                    'total_io_write_mb': round(data['io_write_bytes_total'] / (1024*1024), 2),
                    'max_cpu_percent': data['max_cpu_percent'],
                    'max_memory_rss_mb': round(data['max_memory_rss'] / (1024*1024), 2),
                    'max_io_bytes': data['max_io_bytes'],
                    'total_samples': data['sample_count']
                }
                for proc_name, data in process_aggregates.items()
            }
        }


def run_process_monitoring(config_path: Optional[str] = None) -> Dict:
    """
    Main function to run process monitoring
    """
    # Default configuration
    config = {
        'monitor_interval': 5,  # seconds
        'retention_hours': 24,
        'collect_continuous': False,  # Set to True for continuous monitoring
        'top_processes_count': 10
    }
    
    if config_path:
        try:
            with open(config_path, 'r') as f:
                config.update(json.load(f))
        except FileNotFoundError:
            print(f"Config file {config_path} not found, using defaults")
    
    # Create a monitor instance
    monitor = ProcessMonitor(config)
    
    if config.get('collect_continuous', False):
        print("Starting continuous process monitoring...")
        monitor.start_monitoring()
        # Let it run for a few seconds to collect data
        time.sleep(10)
        monitor.stop_monitoring()
    else:
        # Collect a snapshot
        pass
    
    # Generate reports
    summary_report = monitor.generate_process_summary_report()
    performance_report = monitor.generate_process_performance_report()
    
    return {
        'process_summary_report': summary_report,
        'process_performance_report': performance_report
    }


if __name__ == "__main__":
    report = run_process_monitoring()
    print(json.dumps(report, indent=2))