"""
SMTP/Mail Log Parser
Parses SMTP mail logs for threat detection
"""

import re
from datetime import datetime
from typing import Optional, Dict, List
from dataclasses import dataclass

@dataclass
class SMTPLogEntry:
    timestamp: datetime
    ip_address: str
    sender: str
    recipient: str
    status: str
    raw_log: str = ""

class SMTPParser:
    """Parser for SMTP mail logs"""
    
    def __init__(self):
        # Postfix log format pattern
        self.log_pattern = re.compile(
            r'(?P<timestamp>\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+'
            r'postfix/\w+\[(?P<pid>\d+)\]:\s+'
            r'(?P<ip>\d+\.\d+\.\d+\.\d+):\s+'
            r'to=<(?P<recipient>[^>]+)>.*'
            r'status=(?P<status>\w+)'
        )
        
        # Alternative pattern for rejected messages
        self.reject_pattern = re.compile(
            r'(?P<timestamp>\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+'
            r'postfix/\w+\[(?P<pid>\d+)\]:\s+'
            r'NOQUEUE:\s+reject:\s+RCPT\s+from\s+'
            r'(?P<ip>\d+\.\d+\.\d+\.\d+)'
        )
        
    def parse(self, raw_log: str) -> Optional[SMTPLogEntry]:
        """Parse a single SMTP log entry"""
        try:
            match = self.log_pattern.match(raw_log.strip())
            if not match:
                # Try reject pattern
                match = self.reject_pattern.match(raw_log.strip())
                if not match:
                    return None
                
                data = match.groupdict()
                timestamp = datetime.strptime(data['timestamp'], '%b %d %H:%M:%S')
                timestamp = timestamp.replace(year=datetime.now().year)
                
                return SMTPLogEntry(
                    timestamp=timestamp,
                    ip_address=data['ip'],
                    sender="unknown",
                    recipient="unknown",
                    status="rejected",
                    raw_log=raw_log
                )
                
            data = match.groupdict()
            
            # Parse timestamp (format: May 08 13:00:00)
            timestamp = datetime.strptime(data['timestamp'], '%b %d %H:%M:%S')
            timestamp = timestamp.replace(year=datetime.now().year)
            
            return SMTPLogEntry(
                timestamp=timestamp,
                ip_address=data['ip'],
                sender="unknown",
                recipient=data['recipient'],
                status=data['status'],
                raw_log=raw_log
            )
            
        except Exception as e:
            print(f"Error parsing SMTP log: {e}")
            return None
    
    def parse_batch(self, raw_logs: List[str]) -> List[SMTPLogEntry]:
        """Parse multiple SMTP log entries"""
        parsed_logs = []
        for log in raw_logs:
            parsed = self.parse(log)
            if parsed:
                parsed_logs.append(parsed)
        return parsed_logs
    
    def detect_threats(self, logs: List[SMTPLogEntry]) -> List[Dict]:
        """Detect threats in SMTP logs"""
        threats = []
        
        # Group by IP
        ip_emails = {}
        for log in logs:
            if log.ip_address not in ip_emails:
                ip_emails[log.ip_address] = []
            ip_emails[log.ip_address].append(log)
        
        # Detect suspicious email patterns
        for ip, ip_logs in ip_emails.items():
            # Check for spam patterns (many rejected messages)
            rejected_count = sum(1 for log in ip_logs if log.status == "rejected")
            if rejected_count > 20 and len(ip_logs) > 25:
                threats.append({
                    'type': 'spam_attempt',
                    'ip': ip,
                    'rejected_count': rejected_count,
                    'total_attempts': len(ip_logs)
                })
            
            # Check for email bombing (many recipients)
            unique_recipients = len(set(log.recipient for log in ip_logs if log.recipient != "unknown"))
            if unique_recipients > 50 and len(ip_logs) > 60:
                threats.append({
                    'type': 'email_bombing',
                    'ip': ip,
                    'unique_recipients': unique_recipients,
                    'total_emails': len(ip_logs)
                })
            
            # Check for high failure rate
            failure_rate = sum(1 for log in ip_logs if log.status != "sent") / len(ip_logs)
            if failure_rate > 0.8 and len(ip_logs) > 10:
                threats.append({
                    'type': 'high_email_failure_rate',
                    'ip': ip,
                    'failure_rate': failure_rate,
                    'total_attempts': len(ip_logs)
                })
        
        return threats
