#!/usr/bin/env python3
"""
Storage and Filesystem Monitoring Module
Provides comprehensive tracking of storage usage, performance, and health
"""

import json
import datetime
import psutil
import os
import subprocess
from typing import Dict, List, Optional
from dataclasses import dataclass
from collections import defaultdict
import time
import threading
import shutil


@dataclass
class DiskInfo:
    """Data structure for disk information"""
    device: str
    mount_point: str
    filesystem_type: str
    total_size: int
    used_size: int
    free_size: int
    percent_used: float
    inodes_total: int
    inodes_used: int
    inodes_free: int
    inodes_percent_used: float


@dataclass
class StoragePerformanceRecord:
    """Data structure for storage performance records"""
    timestamp: datetime.datetime
    device: str
    read_count: int
    write_count: int
    read_bytes: int
    write_bytes: int
    read_time: float  # ms
    write_time: float  # ms


@dataclass
class FilesystemEvent:
    """Data structure for filesystem events (created, deleted, accessed, etc.)"""
    timestamp: datetime.datetime
    action: str  # created, modified, deleted, accessed
    path: str
    size: int
    owner: str
    permissions: str


class StorageMonitor:
    """Monitors and tracks storage and filesystem performance"""
    
    def __init__(self, config: Dict):
        self.config = config
        self.performance_history = []
        self.filesystem_events = []
        self.monitoring = False
        self.monitor_thread = None
        
    def get_disk_info(self) -> List[DiskInfo]:
        """Get information about all mounted filesystems"""
        disks = []
        
        # Get partition information
        partitions = psutil.disk_partitions(all=False)
        
        for partition in partitions:
            try:
                # Get usage statistics
                usage = psutil.disk_usage(partition.mountpoint)
                
                # Get inode information (not available on all systems)
                inodes_total = 0
                inodes_used = 0
                inodes_free = 0
                inodes_percent_used = 0.0
                
                try:
                    # This is a system call specific to Unix-like systems
                    statvfs = os.statvfs(partition.mountpoint)
                    inodes_total = statvfs.f_files
                    inodes_free = statvfs.f_ffree
                    inodes_used = inodes_total - inodes_free
                    if inodes_total > 0:
                        inodes_percent_used = (inodes_used / inodes_total) * 100
                except (OSError, AttributeError):
                    # statvfs not available on this system
                    pass
                
                disk_info = DiskInfo(
                    device=partition.device,
                    mount_point=partition.mountpoint,
                    filesystem_type=partition.fstype,
                    total_size=usage.total,
                    used_size=usage.used,
                    free_size=usage.free,
                    percent_used=(usage.used / usage.total) * 100 if usage.total > 0 else 0,
                    inodes_total=inodes_total,
                    inodes_used=inodes_used,
                    inodes_free=inodes_free,
                    inodes_percent_used=inodes_percent_used
                )
                
                disks.append(disk_info)
                
            except PermissionError:
                # This can happen on some systems where certain drives are not accessible
                continue
        
        return disks
    
    def get_storage_performance(self) -> List[StoragePerformanceRecord]:
        """Get storage performance metrics"""
        records = []
        timestamp = datetime.datetime.now()
        
        # Get disk I/O stats
        disk_io_stats = psutil.disk_io_counters(perdisk=True)
        
        for device, stats in disk_io_stats.items():
            record = StoragePerformanceRecord(
                timestamp=timestamp,
                device=device,
                read_count=stats.read_count,
                write_count=stats.write_count,
                read_bytes=stats.read_bytes,
                write_bytes=stats.write_bytes,
                read_time=stats.read_time,
                write_time=stats.write_time
            )
            records.append(record)
        
        return records
    
    def get_top_directories(self, base_path: str = "/", count: int = 10) -> List[Dict]:
        """Get top directories by disk usage"""
        if not os.path.exists(base_path):
            return []
        
        directories_usage = []
        
        # Limit to just the immediate subdirectories to avoid long scans
        try:
            with os.scandir(base_path) as entries:
                for entry in entries:
                    if entry.is_dir(follow_symlinks=False):
                        total_size = 0
                        file_count = 0
                        try:
                            # Just get size of immediate directory contents
                            with os.scandir(entry.path) as subdir_entries:
                                for subentry in subdir_entries:
                                    file_count += 1
                                    try:
                                        total_size += subentry.stat().st_size
                                    except (OSError, FileNotFoundError):
                                        continue
                        except PermissionError:
                            continue
                        
                        if total_size > 0:
                            directories_usage.append({
                                'path': entry.path,
                                'size_bytes': total_size,
                                'size_mb': total_size / (1024 * 1024),
                                'file_count': file_count
                            })
        except PermissionError:
            return []
        
        # Sort by size and return top N
        top_dirs = sorted(directories_usage, key=lambda x: x['size_bytes'], reverse=True)[:count]
        return top_dirs
    
    def start_monitoring(self):
        """Start continuous storage monitoring in a background thread"""
        if self.monitoring:
            return
        
        self.monitoring = True
        self.monitor_thread = threading.Thread(target=self._monitor_loop)
        self.monitor_thread.daemon = True
        self.monitor_thread.start()
    
    def stop_monitoring(self):
        """Stop continuous storage monitoring"""
        self.monitoring = False
        if self.monitor_thread:
            self.monitor_thread.join()
    
    def _monitor_loop(self):
        """Internal monitoring loop"""
        while self.monitoring:
            try:
                # Collect storage performance data
                records = self.get_storage_performance()
                
                # Store in history
                self.performance_history.extend(records)
                
                # Apply retention policy
                self._apply_retention_policy()
                
                # Wait before next collection
                time.sleep(self.config.get('monitor_interval', 5))
                
            except Exception as e:
                print(f"Error in storage monitoring loop: {e}")
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
    
    def generate_storage_summary_report(self) -> Dict:
        """Generate a summary report of storage usage"""
        disks = self.get_disk_info()
        
        if not disks:
            return {"message": "No storage devices found"}
        
        # Calculate overall statistics
        total_size = sum(d.total_size for d in disks)
        total_used = sum(d.used_size for d in disks)
        total_free = sum(d.free_size for d in disks)
        
        # Get top directories for the root filesystem (or main system drive)
        main_mount = "/"
        for disk in disks:
            if disk.mount_point == "/":
                main_mount = disk.mount_point
                break
        top_directories = self.get_top_directories(main_mount, 10)
        
        return {
            'report_type': 'Storage Summary Report',
            'generated_at': datetime.datetime.now().isoformat(),
            'summary': {
                'total_storage_size_bytes': total_size,
                'total_used_bytes': total_used,
                'total_free_bytes': total_free,
                'overall_percent_used': round((total_used / total_size) * 100, 2) if total_size > 0 else 0,
                'total_filesystems': len(disks)
            },
            'filesystems': [
                {
                    'device': disk.device,
                    'mount_point': disk.mount_point,
                    'filesystem_type': disk.filesystem_type,
                    'total_size_gb': round(disk.total_size / (1024**3), 2),
                    'used_size_gb': round(disk.used_size / (1024**3), 2),
                    'free_size_gb': round(disk.free_size / (1024**3), 2),
                    'percent_used': round(disk.percent_used, 2),
                    'inodes_total': disk.inodes_total,
                    'inodes_used': disk.inodes_used,
                    'inodes_free': disk.inodes_free,
                    'inodes_percent_used': round(disk.inodes_percent_used, 2)
                }
                for disk in disks
            ],
            'top_directories_by_size': top_directories
        }
    
    def generate_storage_performance_report(self) -> Dict:
        """Generate a report on storage performance over time"""
        if not self.performance_history:
            # Get a snapshot if no history
            records = self.get_storage_performance()
            self.performance_history.extend(records)
        
        # Aggregate data by device
        device_aggregates = defaultdict(lambda: {
            'read_count_total': 0,
            'write_count_total': 0,
            'read_bytes_total': 0,
            'write_bytes_total': 0,
            'read_time_total': 0,
            'write_time_total': 0,
            'sample_count': 0
        })
        
        for record in self.performance_history:
            device = record.device
            device_aggregates[device]['read_count_total'] += record.read_count
            device_aggregates[device]['write_count_total'] += record.write_count
            device_aggregates[device]['read_bytes_total'] += record.read_bytes
            device_aggregates[device]['write_bytes_total'] += record.write_bytes
            device_aggregates[device]['read_time_total'] += record.read_time
            device_aggregates[device]['write_time_total'] += record.write_time
            device_aggregates[device]['sample_count'] += 1
        
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
            'report_type': 'Storage Performance Report',
            'generated_at': datetime.datetime.now().isoformat(),
            'time_range': time_range,
            'summary': {
                'total_samples': len(self.performance_history),
                'unique_devices_tracked': len(device_aggregates)
            },
            'device_performance_breakdown': {
                device: {
                    'total_read_operations': data['read_count_total'],
                    'total_write_operations': data['write_count_total'],
                    'total_read_bytes': data['read_bytes_total'],
                    'total_write_bytes': data['write_bytes_total'],
                    'total_read_time_ms': data['read_time_total'],
                    'total_write_time_ms': data['write_time_total'],
                    'avg_read_operations': round(data['read_count_total'] / data['sample_count'], 2) if data['sample_count'] > 0 else 0,
                    'avg_write_operations': round(data['write_count_total'] / data['sample_count'], 2) if data['sample_count'] > 0 else 0,
                    'avg_read_bytes': round(data['read_bytes_total'] / data['sample_count'], 2) if data['sample_count'] > 0 else 0,
                    'avg_write_bytes': round(data['write_bytes_total'] / data['sample_count'], 2) if data['sample_count'] > 0 else 0,
                    'total_samples': data['sample_count']
                }
                for device, data in device_aggregates.items()
            }
        }


def run_storage_monitoring(config_path: Optional[str] = None) -> Dict:
    """
    Main function to run storage monitoring
    """
    # Default configuration
    config = {
        'monitor_interval': 5,  # seconds
        'retention_hours': 24,
        'collect_continuous': False,  # Set to True for continuous monitoring
        'top_directories_count': 10
    }
    
    if config_path:
        try:
            with open(config_path, 'r') as f:
                config.update(json.load(f))
        except FileNotFoundError:
            print(f"Config file {config_path} not found, using defaults")
    
    # Create a monitor instance
    monitor = StorageMonitor(config)
    
    if config.get('collect_continuous', False):
        print("Starting continuous storage monitoring...")
        monitor.start_monitoring()
        # Let it run for a few seconds to collect data
        time.sleep(10)
        monitor.stop_monitoring()
    else:
        # Collect a snapshot
        pass
    
    # Generate reports
    summary_report = monitor.generate_storage_summary_report()
    performance_report = monitor.generate_storage_performance_report()
    
    return {
        'storage_summary_report': summary_report,
        'storage_performance_report': performance_report
    }


if __name__ == "__main__":
    report = run_storage_monitoring()
    print(json.dumps(report, indent=2))