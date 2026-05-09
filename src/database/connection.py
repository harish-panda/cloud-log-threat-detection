"""
Database Connection Module
Handles PostgreSQL database connections and operations for the threat detection system
"""

import os
import logging
import psycopg2
from psycopg2.extras import RealDictCursor, DictCursor
from psycopg2.pool import ThreadedConnectionPool
from contextlib import contextmanager
from typing import Dict, List, Optional, Any
from datetime import datetime

from ..parsers.ssh_parser import ParsedLogEntry

logger = logging.getLogger(__name__)

# Global database connection instance
_db_connection = None

def get_db_connection():
    """Get global database connection instance"""
    global _db_connection
    if _db_connection is None:
        _db_connection = DatabaseConnection()
    return _db_connection

class DatabaseConnection:
    """Database connection manager for PostgreSQL"""
    
    def __init__(self, connection_string: str = None):
        """
        Initialize database connection
        
        Args:
            connection_string: PostgreSQL connection string
        """
        self.connection_string = connection_string or os.getenv('DATABASE_URL')
        if not self.connection_string:
            raise ValueError("Database connection string not provided")
        
        self.pool = None
        self._initialize_pool()
    
    def _initialize_pool(self):
        """Initialize connection pool"""
        try:
            self.pool = ThreadedConnectionPool(
                minconn=1,
                maxconn=10,
                dsn=self.connection_string
            )
            logger.info("Database connection pool initialized successfully")
        except Exception as e:
            logger.error(f"Failed to initialize database pool: {e}")
            raise
    
    @contextmanager
    def get_connection(self):
        """Get database connection from pool"""
        connection = None
        try:
            connection = self.pool.getconn()
            yield connection
        except Exception as e:
            if connection:
                connection.rollback()
            logger.error(f"Database connection error: {e}")
            raise
        finally:
            if connection:
                self.pool.putconn(connection)
    
    @contextmanager
    def get_cursor(self, dictionary_cursor=True):
        """Get database cursor from connection"""
        with self.get_connection() as connection:
            cursor_type = RealDictCursor if dictionary_cursor else DictCursor
            cursor = connection.cursor(cursor_factory=cursor_type)
            try:
                yield cursor
                connection.commit()
            except Exception as e:
                connection.rollback()
                logger.error(f"Database cursor error: {e}")
                raise
            finally:
                cursor.close()
    
    def test_connection(self) -> bool:
        """Test database connection"""
        try:
            with self.get_cursor() as cursor:
                cursor.execute("SELECT 1")
                result = cursor.fetchone()
                return result is not None
        except Exception as e:
            logger.error(f"Database connection test failed: {e}")
            return False
    
    def insert_log_entry(self, log_entry: ParsedLogEntry) -> Optional[str]:
        """
        Insert parsed log entry into database
        
        Args:
            log_entry: ParsedLogEntry object
            
        Returns:
            Log entry ID or None if failed
        """
        try:
            with self.get_cursor() as cursor:
                query = """
                INSERT INTO security_logs (
                    timestamp, source, pid, action, details, username, 
                    ip_address, port, event_type, raw_log
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                RETURNING id
                """
                
                cursor.execute(query, (
                    log_entry.timestamp,
                    log_entry.source,
                    log_entry.pid,
                    log_entry.action,
                    log_entry.details,
                    log_entry.username,
                    log_entry.ip_address,
                    log_entry.port,
                    log_entry.event_type,
                    log_entry.raw_log
                ))
                
                result = cursor.fetchone()
                return str(result['id']) if result else None
                
        except Exception as e:
            logger.error(f"Failed to insert log entry: {e}")
            return None
    
    def insert_log_batch(self, log_entries: List[ParsedLogEntry]) -> int:
        """
        Insert multiple log entries in batch
        
        Args:
            log_entries: List of ParsedLogEntry objects
            
        Returns:
            Number of successfully inserted entries
        """
        if not log_entries:
            return 0
        
        try:
            with self.get_cursor() as cursor:
                query = """
                INSERT INTO security_logs (
                    timestamp, source, pid, action, details, username, 
                    ip_address, port, event_type, raw_log
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                """
                
                values = [
                    (
                        entry.timestamp,
                        entry.source,
                        entry.pid,
                        entry.action,
                        entry.details,
                        entry.username,
                        entry.ip_address,
                        entry.port,
                        entry.event_type,
                        entry.raw_log
                    )
                    for entry in log_entries
                ]
                
                cursor.executemany(query, values)
                return cursor.rowcount
                
        except Exception as e:
            logger.error(f"Failed to insert log batch: {e}")
            return 0
    
    def get_recent_logs(self, hours: int = 24, limit: int = 1000) -> List[Dict]:
        """
        Get recent security logs
        
        Args:
            hours: Number of hours to look back
            limit: Maximum number of records to return
            
        Returns:
            List of log entries
        """
        try:
            with self.get_cursor() as cursor:
                query = f"""
                SELECT id, timestamp, source, pid, action, details, 
                       username, ip_address, port, event_type, raw_log, processed_at
                FROM security_logs
                WHERE timestamp >= NOW() - INTERVAL '{hours} hour'
                ORDER BY timestamp DESC
                LIMIT {limit}
                """
                
                cursor.execute(query)
                return cursor.fetchall()
                
        except Exception as e:
            logger.error(f"Failed to get recent logs: {e}")
            return []
    
    def get_failed_logins_by_ip(self, hours: int = 1) -> List[Dict]:
        """
        Get failed login attempts grouped by IP address
        
        Args:
            hours: Number of hours to look back
            
        Returns:
            List of IP addresses with failed login counts
        """
        try:
            with self.get_cursor() as cursor:
                query = """
                SELECT 
                    ip_address,
                    COUNT(*) as failed_count,
                    MIN(timestamp) as first_attempt,
                    MAX(timestamp) as last_attempt,
                    array_agg(DISTINCT username) as targeted_users
                FROM security_logs
                WHERE event_type = 'failed_login'
                AND timestamp >= NOW() - make_interval(hours => %s)
                AND ip_address IS NOT NULL
                GROUP BY ip_address
                HAVING COUNT(*) >= %s
                ORDER BY failed_count DESC
                """
                
                # Get threshold from config
                threshold = self.get_config_value('alert_threshold_failed_logins', '10')
                cursor.execute(query, (hours, int(threshold)))
                return cursor.fetchall()
                
        except Exception as e:
            logger.error(f"Failed to get failed logins by IP: {e}")
            return []
    
    def create_threat_alert(self, threat_type: str, severity: str, 
                          source_ip: str = None, target_user: str = None,
                          description: str = None, confidence_score: float = 0.0,
                          raw_evidence: Dict = None) -> Optional[str]:
        """
        Create a threat alert
        
        Args:
            threat_type: Type of threat
            severity: Severity level
            source_ip: Source IP address
            target_user: Target username
            description: Alert description
            confidence_score: ML confidence score
            raw_evidence: Raw evidence data
            
        Returns:
            Alert ID or None if failed
        """
        try:
            import json
            with self.get_cursor() as cursor:
                query = """
                INSERT INTO threat_alerts (
                    timestamp, threat_type, severity, source_ip, target_user,
                    description, confidence_score, raw_evidence
                ) VALUES (NOW(), %s, %s, %s, %s, %s, %s, %s)
                RETURNING id
                """
                
                # Convert dict to JSON for PostgreSQL JSONB
                raw_evidence_json = json.dumps(raw_evidence) if raw_evidence else None
                
                cursor.execute(query, (
                    threat_type, severity, source_ip, target_user,
                    description, confidence_score, raw_evidence_json
                ))
                
                result = cursor.fetchone()
                return str(result['id']) if result else None
                
        except Exception as e:
            logger.error(f"Failed to create threat alert: {e}")
            return None
    
    def get_config_value(self, key: str, default: str = None) -> Optional[str]:
        """
        Get configuration value from database
        
        Args:
            key: Configuration key
            default: Default value if not found
            
        Returns:
            Configuration value or default
        """
        try:
            with self.get_cursor() as cursor:
                query = "SELECT value FROM system_config WHERE key = %s"
                cursor.execute(query, (key,))
                result = cursor.fetchone()
                return result['value'] if result else default
                
        except Exception as e:
            logger.error(f"Failed to get config value for {key}: {e}")
            return default
    
    def update_config_value(self, key: str, value: str, description: str = None) -> bool:
        """
        Update configuration value
        
        Args:
            key: Configuration key
            value: Configuration value
            description: Optional description
            
        Returns:
            True if successful, False otherwise
        """
        try:
            with self.get_cursor() as cursor:
                query = """
                INSERT INTO system_config (key, value, description, updated_at)
                VALUES (%s, %s, %s, NOW())
                ON CONFLICT (key) 
                DO UPDATE SET 
                    value = EXCLUDED.value,
                    description = COALESCE(EXCLUDED.description, %s),
                    updated_at = NOW()
                """
                
                cursor.execute(query, (key, value, description, description))
                return True
                
        except Exception as e:
            logger.error(f"Failed to update config value for {key}: {e}")
            return False
    
    def get_daily_statistics(self, date: datetime = None) -> Optional[Dict]:
        """
        Get daily statistics for a specific date
        
        Args:
            date: Date to get statistics for (defaults to today)
            
        Returns:
            Statistics dictionary or None
        """
        if date is None:
            date = datetime.now()
        
        try:
            with self.get_cursor() as cursor:
                query = """
                SELECT 
                    total_logs,
                    failed_logins,
                    successful_logins,
                    unique_ips,
                    unique_users
                FROM daily_statistics
                WHERE date = %s
                """
                
                cursor.execute(query, (date.date(),))
                result = cursor.fetchone()
                return dict(result) if result else None
                
        except Exception as e:
            logger.error(f"Failed to get daily statistics: {e}")
            return None
    
    def close(self):
        """Close database connection pool"""
        if self.pool:
            self.pool.closeall()
            logger.info("Database connection pool closed")
