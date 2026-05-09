"""
DNS Log Parser
Parses DNS query logs for threat detection
"""

import re
from datetime import datetime
from typing import Optional, Dict, List
from dataclasses import dataclass

@dataclass
class DNSLogEntry:
    timestamp: datetime
    ip_address: str
    domain: str
    query_type: str
    raw_log: str = ""

class DNSParser:
    """Parser for DNS query logs"""
    
    def __init__(self):
        # Common DNS log format
        self.log_pattern = re.compile(
            r'(?P<timestamp>\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+'
            r'\w+\[(?P<pid>\d+)\]:\s+'
            r'query:\s+(?P<domain>\S+)\s+IN\s+(?P<query_type>\w+)\s+from\s+(?P<ip>\d+\.\d+\.\d+\.\d+)'
        )
        
    def parse(self, raw_log: str) -> Optional[DNSLogEntry]:
        """Parse a single DNS log entry"""
        try:
            match = self.log_pattern.match(raw_log.strip())
            if not match:
                return None
                
            data = match.groupdict()
            
            # Parse timestamp (format: May 08 13:00:00)
            timestamp = datetime.strptime(data['timestamp'], '%b %d %H:%M:%S')
            timestamp = timestamp.replace(year=datetime.now().year)
            
            return DNSLogEntry(
                timestamp=timestamp,
                ip_address=data['ip'],
                domain=data['domain'],
                query_type=data['query_type'],
                raw_log=raw_log
            )
            
        except Exception as e:
            print(f"Error parsing DNS log: {e}")
            return None
    
    def parse_batch(self, raw_logs: List[str]) -> List[DNSLogEntry]:
        """Parse multiple DNS log entries"""
        parsed_logs = []
        for log in raw_logs:
            parsed = self.parse(log)
            if parsed:
                parsed_logs.append(parsed)
        return parsed_logs
    
    def detect_threats(self, logs: List[DNSLogEntry]) -> List[Dict]:
        """Detect threats in DNS logs"""
        threats = []
        
        # Group by IP
        ip_queries = {}
        for log in logs:
            if log.ip_address not in ip_queries:
                ip_queries[log.ip_address] = []
            ip_queries[log.ip_address].append(log)
        
        # Detect suspicious DNS patterns
        for ip, ip_logs in ip_queries.items():
            # Check for DGA (Domain Generation Algorithm) patterns
            unique_domains = len(set(log.domain for log in ip_logs))
            if unique_domains > 50 and len(ip_logs) > 100:
                threats.append({
                    'type': 'dga_activity',
                    'ip': ip,
                    'unique_domains': unique_domains,
                    'queries': len(ip_logs)
                })
            
            # Check for queries to known malicious domains
            malicious_domains = ['malicious-site.com', 'suspicious-domain.net', 'botnet-server.info']
            malicious_queries = [log.domain for log in ip_logs if any(md in log.domain for md in malicious_domains)]
            if malicious_queries:
                threats.append({
                    'type': 'malicious_domain_query',
                    'ip': ip,
                    'domains': list(set(malicious_queries))
                })
            
            # Check for high query rate
            if len(ip_logs) > 200:
                time_span = (max(log.timestamp for log in ip_logs) - min(log.timestamp for log in ip_logs)).total_seconds()
                if time_span > 0:
                    qps = len(ip_logs) / time_span
                    if qps > 10:  # More than 10 queries per second
                        threats.append({
                            'type': 'high_query_rate',
                            'ip': ip,
                            'qps': qps,
                            'total_queries': len(ip_logs)
                        })
        
        return threats
