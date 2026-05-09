"""
HTTP Access Log Parser
Parses Apache/Nginx access logs for threat detection
"""

import re
from datetime import datetime
from typing import Optional, Dict
from dataclasses import dataclass

@dataclass
class HTTPLogEntry:
    timestamp: datetime
    ip_address: str
    method: str
    path: str
    status_code: int
    size: int
    user_agent: str
    referer: str = ""
    raw_log: str = ""

class HTTPParser:
    """Parser for HTTP access logs"""
    
    def __init__(self):
        # Apache/Nginx common log format pattern
        self.log_pattern = re.compile(
            r'(?P<ip>\d+\.\d+\.\d+\.\d+) - - \[(?P<timestamp>[^\]]+)\] '
            r'"(?P<method>\w+) (?P<path>[^\s]+) HTTP/\d\.\d" '
            r'(?P<status>\d+) (?P<size>\d+) '
            r'"(?P<referer>[^"]*)" "(?P<user_agent>[^"]*)"'
        )
        
    def parse(self, raw_log: str) -> Optional[HTTPLogEntry]:
        """Parse a single HTTP access log entry"""
        try:
            match = self.log_pattern.match(raw_log.strip())
            if not match:
                return None
                
            data = match.groupdict()
            
            # Parse timestamp (format: 08/May/2026:13:00:00)
            timestamp = datetime.strptime(data['timestamp'], '%d/%b/%Y:%H:%M:%S')
            
            return HTTPLogEntry(
                timestamp=timestamp,
                ip_address=data['ip'],
                method=data['method'],
                path=data['path'],
                status_code=int(data['status']),
                size=int(data['size']),
                user_agent=data['user_agent'],
                referer=data['referer'],
                raw_log=raw_log
            )
            
        except Exception as e:
            print(f"Error parsing HTTP log: {e}")
            return None
    
    def parse_batch(self, raw_logs: list) -> list:
        """Parse multiple HTTP log entries"""
        parsed_logs = []
        for log in raw_logs:
            parsed = self.parse(log)
            if parsed:
                parsed_logs.append(parsed)
        return parsed_logs
    
    def detect_threats(self, logs: list) -> list:
        """Detect threats in HTTP logs"""
        threats = []
        
        # Group by IP
        ip_requests = {}
        for log in logs:
            if log.ip_address not in ip_requests:
                ip_requests[log.ip_address] = []
            ip_requests[log.ip_address].append(log)
        
        # Detect suspicious patterns
        for ip, ip_logs in ip_requests.items():
            # Check for too many 4xx/5xx errors
            error_rate = sum(1 for log in ip_logs if log.status_code >= 400) / len(ip_logs)
            if error_rate > 0.5 and len(ip_logs) > 10:
                threats.append({
                    'type': 'high_error_rate',
                    'ip': ip,
                    'error_rate': error_rate,
                    'requests': len(ip_logs)
                })
            
            # Check for scanning patterns (many different paths)
            unique_paths = len(set(log.path for log in ip_logs))
            if unique_paths > 20 and len(ip_logs) > 30:
                threats.append({
                    'type': 'directory_scanning',
                    'ip': ip,
                    'unique_paths': unique_paths,
                    'requests': len(ip_logs)
                })
            
            # Check for SQL injection attempts
            suspicious_paths = [log.path for log in ip_logs if any(pattern in log.path.lower() for pattern in ['sql', 'union', 'select', 'drop', 'insert'])]
            if suspicious_paths:
                threats.append({
                    'type': 'sql_injection_attempt',
                    'ip': ip,
                    'attempts': len(suspicious_paths)
                })
        
        return threats
