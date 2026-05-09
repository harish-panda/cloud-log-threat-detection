"""
SSH Log Parser Module
Parses SSH authentication logs into structured data for threat detection
"""

import re
import logging
from datetime import datetime
from typing import Dict, Optional, List
from dataclasses import dataclass

logger = logging.getLogger(__name__)

@dataclass
class ParsedLogEntry:
    """Structured representation of a parsed log entry"""
    timestamp: datetime
    source: str
    pid: int
    action: str
    details: str
    username: Optional[str] = None
    ip_address: Optional[str] = None
    port: Optional[int] = None
    event_type: Optional[str] = None
    raw_log: str = ""

class SSHLogParser:
    """Parser for SSH authentication logs"""
    
    def __init__(self):
        # SSH log pattern: Apr 07 00:58:03 server sshd[3329]: Accepted password for sysadmin from 10.0.133.201 port 46269
        self.ssh_pattern = re.compile(
            r'(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(\w+)\s+sshd\[(\d+)\]:\s+(.+)'
        )
        
        # Failed login pattern: Failed password for user from ip port port
        self.failed_pattern = re.compile(
            r'Failed password for (\w+) from ([\d\.]+) port (\d+)'
        )
        
        # Successful login pattern: Accepted password for user from ip port port
        self.success_pattern = re.compile(
            r'Accepted password for (\w+) from ([\d\.]+) port (\d+)'
        )
        
        # Invalid user pattern: Invalid user user from ip
        self.invalid_user_pattern = re.compile(
            r'Invalid user (\w+) from ([\d\.]+)'
        )
    
    def parse(self, log_entry: str) -> Optional[ParsedLogEntry]:
        """
        Parse a single SSH log entry
        
        Args:
            log_entry: Raw log entry string
            
        Returns:
            ParsedLogEntry or None if parsing fails
        """
        try:
            match = self.ssh_pattern.match(log_entry.strip())
            if not match:
                logger.warning(f"Failed to match SSH log pattern: {log_entry}")
                return None
            
            timestamp_str, hostname, pid_str, details = match.groups()
            
            # Parse timestamp
            timestamp = self._parse_timestamp(timestamp_str)
            if not timestamp:
                return None
            
            # Create base entry
            entry = ParsedLogEntry(
                timestamp=timestamp,
                source=hostname,
                pid=int(pid_str),
                action="SSH",
                details=details,
                raw_log=log_entry.strip()
            )
            
            # Extract specific information from details
            self._extract_log_details(entry, details)
            
            return entry
            
        except Exception as e:
            logger.error(f"Error parsing log entry: {e}")
            return None
    
    def _parse_timestamp(self, timestamp_str: str) -> Optional[datetime]:
        """Parse timestamp from log entry"""
        try:
            # Add current year since logs don't include it
            current_year = datetime.now().year
            timestamp_with_year = f"{current_year} {timestamp_str}"
            return datetime.strptime(timestamp_with_year, "%Y %b %d %H:%M:%S")
        except ValueError as e:
            logger.error(f"Failed to parse timestamp '{timestamp_str}': {e}")
            return None
    
    def _extract_log_details(self, entry: ParsedLogEntry, details: str):
        """Extract specific details from log entry"""
        details_lower = details.lower()
        
        if "failed password" in details_lower:
            match = self.failed_pattern.search(details)
            if match:
                entry.username = match.group(1)
                entry.ip_address = match.group(2)
                entry.port = int(match.group(3))
                entry.event_type = "failed_login"
        
        elif "accepted password" in details_lower:
            match = self.success_pattern.search(details)
            if match:
                entry.username = match.group(1)
                entry.ip_address = match.group(2)
                entry.port = int(match.group(3))
                entry.event_type = "successful_login"
        
        elif "invalid user" in details_lower:
            match = self.invalid_user_pattern.search(details)
            if match:
                entry.username = match.group(1)
                entry.ip_address = match.group(2)
                entry.event_type = "invalid_user"
        
        elif "connection closed" in details_lower:
            entry.event_type = "connection_closed"
        
        elif "pam_unix" in details_lower:
            entry.event_type = "authentication_error"
        
        else:
            entry.event_type = "other"
    
    def parse_batch(self, log_entries: List[str]) -> List[ParsedLogEntry]:
        """
        Parse multiple log entries
        
        Args:
            log_entries: List of raw log entry strings
            
        Returns:
            List of ParsedLogEntry objects
        """
        parsed_entries = []
        
        for log_entry in log_entries:
            if not log_entry.strip():  # Skip empty lines
                continue
            
            parsed_entry = self.parse(log_entry)
            if parsed_entry:
                parsed_entries.append(parsed_entry)
        
        logger.info(f"Parsed {len(parsed_entries)} out of {len(log_entries)} log entries")
        return parsed_entries
    
    def validate_log_entry(self, log_entry: str) -> bool:
        """
        Validate if a log entry matches expected SSH log format
        
        Args:
            log_entry: Raw log entry string
            
        Returns:
            True if valid, False otherwise
        """
        return bool(self.ssh_pattern.match(log_entry.strip()))
