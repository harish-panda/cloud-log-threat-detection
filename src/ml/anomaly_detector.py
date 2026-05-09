"""
ML Anomaly Detection Module
Uses Isolation Forest to detect anomalous patterns in SSH logs
"""

import logging
import numpy as np
import pandas as pd
from datetime import datetime, timedelta
from typing import List, Dict, Tuple, Optional
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from sklearn.feature_extraction import DictVectorizer
import joblib
import os

from ..database.connection import DatabaseConnection
from ..parsers.ssh_parser import ParsedLogEntry

logger = logging.getLogger(__name__)

class FeatureExtractor:
    """Extract features from log entries for ML analysis"""
    
    def __init__(self):
        self.vectorizer = DictVectorizer(sparse=False)
        self.scaler = StandardScaler()
        self.feature_names = []
    
    def extract_features_from_logs(self, logs: List[ParsedLogEntry]) -> np.ndarray:
        """
        Extract features from a list of parsed log entries
        
        Args:
            logs: List of ParsedLogEntry objects
            
        Returns:
            Feature matrix
        """
        if not logs:
            return np.array([])
        
        features = []
        
        for log in logs:
            feature_dict = self._extract_single_log_features(log)
            features.append(feature_dict)
        
        # Convert to DataFrame and then to numpy array
        df = pd.DataFrame(features)
        
        # Fill missing values
        df = df.fillna(0)
        
        return df.values
    
    def _extract_single_log_features(self, log: ParsedLogEntry) -> Dict:
        """Extract features from a single log entry"""
        features = {}
        
        # Time-based features
        features['hour'] = log.timestamp.hour
        features['day_of_week'] = log.timestamp.weekday()
        features['day_of_month'] = log.timestamp.day
        features['is_weekend'] = 1 if log.timestamp.weekday() >= 5 else 0
        features['is_night'] = 1 if log.timestamp.hour < 6 or log.timestamp.hour > 22 else 0
        
        # Event type features
        features['is_failed_login'] = 1 if log.event_type == 'failed_login' else 0
        features['is_successful_login'] = 1 if log.event_type == 'successful_login' else 0
        features['is_invalid_user'] = 1 if log.event_type == 'invalid_user' else 0
        features['is_connection_closed'] = 1 if log.event_type == 'connection_closed' else 0
        
        # IP-based features
        if log.ip_address:
            ip_parts = log.ip_address.split('.')
            features['ip_first_octet'] = int(ip_parts[0]) if len(ip_parts) > 0 else 0
            features['ip_second_octet'] = int(ip_parts[1]) if len(ip_parts) > 1 else 0
            features['is_private_ip'] = self._is_private_ip(log.ip_address)
            features['is_localhost'] = 1 if log.ip_address.startswith('127.') or log.ip_address == 'localhost' else 0
        else:
            features['ip_first_octet'] = 0
            features['ip_second_octet'] = 0
            features['is_private_ip'] = 0
            features['is_localhost'] = 0
        
        # User-based features
        features['is_root_user'] = 1 if log.username == 'root' else 0
        features['is_admin_user'] = 1 if log.username in ['admin', 'administrator'] else 0
        features['username_length'] = len(log.username) if log.username else 0
        
        # Process-based features
        features['pid'] = log.pid if log.pid else 0
        features['is_high_pid'] = 1 if log.pid and log.pid > 5000 else 0
        
        return features
    
    def _is_private_ip(self, ip: str) -> int:
        """Check if IP is in private range"""
        try:
            parts = list(map(int, ip.split('.')))
            
            # 10.0.0.0/8
            if parts[0] == 10:
                return 1
            
            # 172.16.0.0/12
            if parts[0] == 172 and 16 <= parts[1] <= 31:
                return 1
            
            # 192.168.0.0/16
            if parts[0] == 192 and parts[1] == 168:
                return 1
            
            return 0
        except:
            return 0
    
    def extract_aggregated_features(self, logs: List[ParsedLogEntry], 
                                  time_window_minutes: int = 5) -> List[Dict]:
        """
        Extract aggregated features over time windows
        
        Args:
            logs: List of ParsedLogEntry objects
            time_window_minutes: Time window for aggregation
            
        Returns:
            List of feature dictionaries
        """
        if not logs:
            return []
        
        # Sort logs by timestamp
        sorted_logs = sorted(logs, key=lambda x: x.timestamp)
        
        aggregated_features = []
        window_start = sorted_logs[0].timestamp
        window_end = window_start + timedelta(minutes=time_window_minutes)
        
        current_window_logs = []
        
        for log in sorted_logs:
            if log.timestamp <= window_end:
                current_window_logs.append(log)
            else:
                # Process current window
                if current_window_logs:
                    features = self._aggregate_window_features(current_window_logs, window_start, window_end)
                    aggregated_features.append(features)
                
                # Start new window
                current_window_logs = [log]
                window_start = log.timestamp
                window_end = window_start + timedelta(minutes=time_window_minutes)
        
        # Process last window
        if current_window_logs:
            features = self._aggregate_window_features(current_window_logs, window_start, window_end)
            aggregated_features.append(features)
        
        return aggregated_features
    
    def _aggregate_window_features(self, logs: List[ParsedLogEntry], 
                                  window_start: datetime, window_end: datetime) -> Dict:
        """Aggregate features for a time window"""
        features = {}
        
        # Basic counts
        features['total_events'] = len(logs)
        features['failed_logins'] = sum(1 for log in logs if log.event_type == 'failed_login')
        features['successful_logins'] = sum(1 for log in logs if log.event_type == 'successful_login')
        features['invalid_users'] = sum(1 for log in logs if log.event_type == 'invalid_user')
        
        # Ratios
        features['failed_login_ratio'] = features['failed_logins'] / features['total_events'] if features['total_events'] > 0 else 0
        features['success_login_ratio'] = features['successful_logins'] / features['total_events'] if features['total_events'] > 0 else 0
        
        # Unique counts
        unique_ips = set(log.ip_address for log in logs if log.ip_address)
        unique_users = set(log.username for log in logs if log.username)
        
        features['unique_ips'] = len(unique_ips)
        features['unique_users'] = len(unique_users)
        
        # Time-based features
        features['hour'] = window_start.hour
        features['day_of_week'] = window_start.weekday()
        features['is_weekend'] = 1 if window_start.weekday() >= 5 else 0
        features['is_night'] = 1 if window_start.hour < 6 or window_start.hour > 22 else 0
        
        # Attack patterns
        features['high_failed_rate'] = 1 if features['failed_login_ratio'] > 0.5 else 0
        features['many_unique_ips'] = 1 if features['unique_ips'] > 10 else 0
        features['brute_force_pattern'] = 1 if features['failed_logins'] > 5 and features['unique_users'] <= 3 else 0
        
        # New threat detection patterns
        # Credential stuffing: many failed logins with different usernames from same IP
        ip_user_pairs = {}
        for log in logs:
            if log.ip_address and log.username and log.event_type == 'failed_login':
                if log.ip_address not in ip_user_pairs:
                    ip_user_pairs[log.ip_address] = set()
                ip_user_pairs[log.ip_address].add(log.username)
        
        max_users_per_ip = max(len(users) for users in ip_user_pairs.values()) if ip_user_pairs else 0
        features['credential_stuffing'] = 1 if max_users_per_ip > 5 else 0
        
        # Account discovery: many invalid user attempts
        features['account_discovery'] = 1 if features['invalid_users'] > 10 else 0
        
        # Port scanning pattern: many different IPs with connection failures
        failed_ips = set(log.ip_address for log in logs if log.event_type == 'failed_login' and log.ip_address)
        features['port_scan_pattern'] = 1 if len(failed_ips) > 15 and features['failed_logins'] < len(failed_ips) * 2 else 0
        
        # Timing anomaly: events happening too quickly or too slowly
        if len(logs) > 1:
            time_diffs = [(logs[i+1].timestamp - logs[i].timestamp).total_seconds() for i in range(len(logs)-1)]
            avg_time_diff = sum(time_diffs) / len(time_diffs) if time_diffs else 0
            features['avg_time_between_events'] = avg_time_diff
            features['timing_anomaly'] = 1 if avg_time_diff < 1 or avg_time_diff > 300 else 0
        else:
            features['avg_time_between_events'] = 0
            features['timing_anomaly'] = 0
        
        # User behavior anomaly: unusual activity for specific user
        user_activity = {}
        for log in logs:
            if log.username:
                if log.username not in user_activity:
                    user_activity[log.username] = {'total': 0, 'failed': 0}
                user_activity[log.username]['total'] += 1
                if log.event_type == 'failed_login':
                    user_activity[log.username]['failed'] += 1
        
        for user, activity in user_activity.items():
            if activity['total'] > 10 and activity['failed'] / activity['total'] > 0.8:
                features['user_anomaly'] = 1
                break
        else:
            features['user_anomaly'] = 0
        
        return features

class AnomalyDetector:
    """Main anomaly detection class using Isolation Forest"""
    
    def __init__(self, model_path: str = None):
        """
        Initialize anomaly detector
        
        Args:
            model_path: Path to saved model file
        """
        self.model = None
        self.feature_extractor = FeatureExtractor()
        self.is_trained = False
        self.model_path = model_path or "models/anomaly_detector.pkl"
        
        # Model parameters
        self.contamination = 0.1  # Expected proportion of anomalies
        self.n_estimators = 100
        self.random_state = 42
        
        # Initialize model
        self.model = IsolationForest(
            contamination=self.contamination,
            n_estimators=self.n_estimators,
            random_state=self.random_state,
            n_jobs=-1
        )
    
    def train(self, logs: List[ParsedLogEntry], use_aggregated: bool = True) -> bool:
        """
        Train the anomaly detection model
        
        Args:
            logs: Training log entries
            use_aggregated: Whether to use aggregated features
            
        Returns:
            True if training successful, False otherwise
        """
        try:
            logger.info(f"Starting training with {len(logs)} log entries")
            
            if use_aggregated:
                # Extract aggregated features
                features_list = self.feature_extractor.extract_aggregated_features(logs)
                
                if not features_list:
                    logger.error("No features extracted for training")
                    return False
                
                # Convert to DataFrame
                df = pd.DataFrame(features_list)
                df = df.fillna(0)
                
                X = df.values
                self.feature_names = df.columns.tolist()
            else:
                # Extract individual log features
                X = self.feature_extractor.extract_features_from_logs(logs)
                
                if X.size == 0:
                    logger.error("No features extracted for training")
                    return False
            
            # Train the model
            self.model.fit(X)
            self.is_trained = True
            
            # Save the model
            self.save_model()
            
            logger.info(f"Model trained successfully with {X.shape[0]} samples and {X.shape[1]} features")
            return True
            
        except Exception as e:
            logger.error(f"Error training model: {e}")
            return False
    
    def detect_anomalies(self, logs: List[ParsedLogEntry], use_aggregated: bool = True) -> List[Dict]:
        """
        Detect anomalies in log entries
        
        Args:
            logs: Log entries to analyze
            use_aggregated: Whether to use aggregated features
            
        Returns:
            List of anomaly results
        """
        if not self.is_trained:
            logger.error("Model not trained yet")
            return []
        
        try:
            anomalies = []
            
            if use_aggregated:
                # Extract aggregated features
                features_list = self.feature_extractor.extract_aggregated_features(logs)
                
                if not features_list:
                    return []
                
                # Convert to DataFrame
                df = pd.DataFrame(features_list)
                df = df.fillna(0)
                
                X = df.values
                
                # Predict anomalies
                predictions = self.model.predict(X)
                scores = self.model.decision_function(X)
                
                # Create results
                for i, (feature_dict, prediction, score) in enumerate(zip(features_list, predictions, scores)):
                    if prediction == -1:  # Anomaly detected
                        anomaly = {
                            'window_start': feature_dict.get('window_start'),
                            'anomaly_score': float(score),
                            'features': feature_dict,
                            'severity': self._calculate_severity(score),
                            'anomaly_type': self._classify_anomaly_type(feature_dict)
                        }
                        anomalies.append(anomaly)
            
            return anomalies
            
        except Exception as e:
            logger.error(f"Error detecting anomalies: {e}")
            return []
    
    def _calculate_severity(self, anomaly_score: float) -> str:
        """Calculate severity based on anomaly score"""
        if anomaly_score < -0.5:
            return "high"
        elif anomaly_score < -0.2:
            return "medium"
        else:
            return "low"
    
    def _classify_anomaly_type(self, features: Dict) -> str:
        """Classify the type of anomaly based on features"""
        if features.get('brute_force_pattern', 0) == 1:
            return "brute_force_attack"
        elif features.get('credential_stuffing', 0) == 1:
            return "credential_stuffing"
        elif features.get('account_discovery', 0) == 1:
            return "account_discovery"
        elif features.get('many_unique_ips', 0) == 1:
            return "distributed_attack"
        elif features.get('high_failed_rate', 0) == 1:
            return "high_failure_rate"
        elif features.get('is_night', 0) == 1 and features.get('failed_logins', 0) > 0:
            return "off_hours_activity"
        elif features.get('port_scan_pattern', 0) == 1:
            return "port_scanning"
        elif features.get('timing_anomaly', 0) == 1:
            return "timing_anomaly"
        elif features.get('user_anomaly', 0) == 1:
            return "user_behavior_anomaly"
        else:
            return "unknown_anomaly"
    
    def save_model(self):
        """Save the trained model to disk"""
        try:
            os.makedirs(os.path.dirname(self.model_path), exist_ok=True)
            joblib.dump({
                'model': self.model,
                'feature_names': self.feature_names,
                'is_trained': self.is_trained,
                'contamination': self.contamination,
                'n_estimators': self.n_estimators
            }, self.model_path)
            logger.info(f"Model saved to {self.model_path}")
        except Exception as e:
            logger.error(f"Error saving model: {e}")
    
    def load_model(self) -> bool:
        """Load a trained model from disk"""
        try:
            if os.path.exists(self.model_path):
                model_data = joblib.load(self.model_path)
                self.model = model_data['model']
                self.feature_names = model_data['feature_names']
                self.is_trained = model_data['is_trained']
                self.contamination = model_data['contamination']
                self.n_estimators = model_data['n_estimators']
                logger.info(f"Model loaded from {self.model_path}")
                return True
            else:
                logger.warning(f"Model file not found: {self.model_path}")
                return False
        except Exception as e:
            logger.error(f"Error loading model: {e}")
            return False
    
    def evaluate_model_performance(self, test_logs=None) -> Dict:
        """
        Evaluate model performance with accuracy, precision, recall, and F1 score
        
        Args:
            test_logs: Optional test dataset, will use recent logs if None
            
        Returns:
            Dictionary with performance metrics
        """
        try:
            if not self.is_trained:
                return {"error": "Model not trained"}
            
            # Get test data if not provided
            if test_logs is None:
                from ..database.connection import DatabaseConnection
                db = DatabaseConnection()
                test_logs = db.get_recent_logs(hours=24, limit=1000)
            
            if not test_logs:
                return {"error": "No test data available"}
            
            # Extract features and create ground truth labels
            features = []
            true_labels = []
            
            for log_data in test_logs:
                # Create feature vector
                feature_vector = self._extract_single_features(log_data)
                features.append(feature_vector)
                
                # Create ground truth label (1 for anomaly, 0 for normal)
                # Based on simple heuristics for ground truth
                is_anomaly = self._create_ground_truth_label(log_data)
                true_labels.append(is_anomaly)
            
            if not features:
                return {"error": "No features extracted"}
            
            features_array = np.array(features)
            
            # Get model predictions
            predictions = self.model.predict(features_array)
            # Convert IsolationForest output (-1 for anomaly, 1 for normal) to binary (1 for anomaly, 0 for normal)
            pred_labels = [1 if p == -1 else 0 for p in predictions]
            
            # Calculate metrics
            from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, classification_report, confusion_matrix
            
            accuracy = accuracy_score(true_labels, pred_labels)
            precision = precision_score(true_labels, pred_labels, average='binary', zero_division=0)
            recall = recall_score(true_labels, pred_labels, average='binary', zero_division=0)
            f1 = f1_score(true_labels, pred_labels, average='binary', zero_division=0)
            
            # Create confusion matrix
            cm = confusion_matrix(true_labels, pred_labels)
            tn, fp, fn, tp = cm.ravel()
            
            # Calculate additional metrics
            specificity = tn / (tn + fp) if (tn + fp) > 0 else 0
            false_positive_rate = fp / (fp + tn) if (fp + tn) > 0 else 0
            false_negative_rate = fn / (fn + tp) if (fn + tp) > 0 else 0
            
            return {
                "accuracy": float(accuracy),
                "precision": float(precision),
                "recall": float(recall),
                "f1_score": float(f1),
                "specificity": float(specificity),
                "false_positive_rate": float(false_positive_rate),
                "false_negative_rate": float(false_negative_rate),
                "true_positives": int(tp),
                "true_negatives": int(tn),
                "false_positives": int(fp),
                "false_negatives": int(fn),
                "total_samples": len(true_labels),
                "anomaly_samples": sum(true_labels),
                "predicted_anomalies": sum(pred_labels),
                "confusion_matrix": cm.tolist(),
                "classification_report": classification_report(true_labels, pred_labels, output_dict=True, zero_division=0)
            }
            
        except Exception as e:
            logger.error(f"Error evaluating model performance: {e}")
            return {"error": str(e)}
    
    def _extract_single_features(self, log_data):
        """Extract features from a single log entry"""
        try:
            features = []
            
            # Time-based features (3)
            if log_data.get('timestamp'):
                timestamp = log_data['timestamp']
                if isinstance(timestamp, str):
                    timestamp = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
                features.append(timestamp.hour)
                features.append(timestamp.weekday())
                features.append(timestamp.hour * 60 + timestamp.minute)  # Minutes from midnight
            else:
                features.extend([0, 0, 0])
            
            # Event type features (4)
            event_type = log_data.get('event_type', 'unknown')
            features.append(1 if event_type == 'failed_login' else 0)
            features.append(1 if event_type == 'successful_login' else 0)
            features.append(1 if event_type == 'invalid_user' else 0)
            features.append(1 if event_type == 'connection_closed' else 0)
            
            # IP-based features (3)
            ip_address = log_data.get('ip_address')
            if ip_address:
                # Simple IP classification
                features.append(1 if ip_address.startswith(('192.168.', '10.', '172.')) else 0)  # Internal IP
                features.append(1 if '.' in str(ip_address) else 0)  # Valid IP format
                features.append(1 if str(ip_address).startswith(('198.51.', '203.0.', '192.0.')) else 0)  # External suspicious IP
            else:
                features.extend([0, 0, 0])
            
            # User-based features (3)
            username = log_data.get('username', '')
            features.append(1 if username in ['admin', 'root', 'sysadmin'] else 0)  # Privileged user
            features.append(1 if username else 0)  # Has username
            features.append(1 if username in ['backup', 'nagios', 'apache', 'mysql'] else 0)  # Service account
            
            # Port features (2)
            port = log_data.get('port', 22)
            features.append(1 if port == 22 else 0)  # Standard SSH port
            features.append(1 if port > 1024 else 0)  # High port
            
            return features
            
        except Exception as e:
            logger.error(f"Error extracting features: {e}")
            return [0] * 15  # Return default features if extraction fails
    
    def _create_ground_truth_label(self, log_data):
        """Create ground truth label based on heuristics"""
        try:
            # Consider as anomaly if:
            # 1. Failed login from external IP
            # 2. Failed login for privileged user
            # 3. Invalid user attempt
            # 4. Off-hours activity (before 6 AM or after 10 PM)
            
            event_type = log_data.get('event_type', '')
            ip_address = log_data.get('ip_address', '')
            username = log_data.get('username', '')
            timestamp = log_data.get('timestamp')
            
            # Check time
            is_off_hours = False
            if timestamp:
                if isinstance(timestamp, str):
                    timestamp = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
                is_off_hours = timestamp.hour < 6 or timestamp.hour > 22
            
            # Check if external IP
            is_external_ip = False
            if ip_address:
                is_external_ip = not ip_address.startswith(('192.168.', '10.', '172.', '127.'))
            
            # Check if privileged user
            is_privileged_user = username in ['admin', 'root', 'sysadmin']
            
            # Determine if anomaly
            if event_type == 'failed_login':
                if is_external_ip or is_privileged_user or is_off_hours:
                    return 1  # Anomaly
            elif event_type == 'invalid_user':
                return 1  # Anomaly
            
            return 0  # Normal
            
        except Exception as e:
            logger.error(f"Error creating ground truth label: {e}")
            return 0  # Default to normal

class ThreatDetectionPipeline:
    """Complete pipeline for threat detection"""
    
    def __init__(self, db_connection: DatabaseConnection):
        """
        Initialize the threat detection pipeline
        
        Args:
            db_connection: Database connection instance
        """
        self.db = db_connection
        self.anomaly_detector = AnomalyDetector()
        
        # Try to load existing model
        self.anomaly_detector.load_model()
    
    def train_model(self, days_back: int = 7) -> bool:
        """
        Train the anomaly detection model with recent data
        
        Args:
            days_back: Number of days of historical data to use
            
        Returns:
            True if training successful
        """
        try:
            # Get recent logs from database
            logs = self.db.get_recent_logs(hours=days_back * 24, limit=50000)
            
            if not logs:
                logger.warning("No logs found for training")
                return False
            
            # Convert to ParsedLogEntry objects
            parsed_logs = []
            for log_data in logs:
                parsed_log = ParsedLogEntry(
                    timestamp=log_data['timestamp'],
                    source=log_data['source'],
                    pid=log_data['pid'],
                    action=log_data['action'],
                    details=log_data['details'],
                    username=log_data['username'],
                    ip_address=log_data['ip_address'],
                    port=log_data['port'],
                    event_type=log_data['event_type'],
                    raw_log=log_data['raw_log']
                )
                parsed_logs.append(parsed_log)
            
            # Train the model
            success = self.anomaly_detector.train(parsed_logs)
            
            if success:
                logger.info(f"Model trained successfully with {len(parsed_logs)} logs")
            else:
                logger.error("Model training failed")
            
            return success
            
        except Exception as e:
            logger.error(f"Error in training pipeline: {e}")
            return False
    
    def detect_threats(self, hours_back: int = 1) -> List[Dict]:
        """
        Detect threats in recent logs
        
        Args:
            hours_back: Number of hours to analyze
            
        Returns:
            List of detected threats
        """
        try:
            # Get recent logs
            logs = self.db.get_recent_logs(hours=hours_back, limit=10000)
            
            if not logs:
                logger.warning("No recent logs found for threat detection")
                return []
            
            # Convert to ParsedLogEntry objects
            parsed_logs = []
            for log_data in logs:
                parsed_log = ParsedLogEntry(
                    timestamp=log_data['timestamp'],
                    source=log_data['source'],
                    pid=log_data['pid'],
                    action=log_data['action'],
                    details=log_data['details'],
                    username=log_data['username'],
                    ip_address=log_data['ip_address'],
                    port=log_data['port'],
                    event_type=log_data['event_type'],
                    raw_log=log_data['raw_log']
                )
                parsed_logs.append(parsed_log)
            
            # Detect anomalies
            anomalies = self.anomaly_detector.detect_anomalies(parsed_logs)
            
            # Create threat alerts for anomalies
            threats = []
            for anomaly in anomalies:
                threat = {
                    'timestamp': datetime.now(),
                    'threat_type': anomaly['anomaly_type'],
                    'severity': anomaly['severity'],
                    'confidence_score': abs(anomaly['anomaly_score']),
                    'description': f"Anomaly detected: {anomaly['anomaly_type']}",
                    'raw_evidence': anomaly['features']
                }
                
                # Create alert in database
                alert_id = self.db.create_threat_alert(
                    threat['threat_type'],
                    threat['severity'],
                    description=threat['description'],
                    confidence_score=threat['confidence_score'],
                    raw_evidence=threat['raw_evidence']
                )
                
                if alert_id:
                    threat['alert_id'] = alert_id
                    threats.append(threat)
            
            logger.info(f"Detected {len(threats)} threats in the last {hours_back} hours")
            return threats
            
        except Exception as e:
            logger.error(f"Error in threat detection pipeline: {e}")
            return []
