#!/usr/bin/env python3
"""
Enhanced Real-Time SIEM System
A comprehensive enterprise security monitoring solution with advanced threat detection,
file integrity monitoring, DNS analysis, user behavior analytics, and compliance reporting.
"""

import os
import sys
import json
import hashlib
import sqlite3
import threading
import time
import datetime
import re
import socket
import struct
import subprocess
import logging
import psutil
from collections import defaultdict, deque
from pathlib import Path
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
import statistics
from typing import Dict, List, Tuple, Optional, Any

# Configuration
CONFIG = {
    'database': 'siem.db',
    'web_port': 8080,
    'log_sources': [
        '/var/log/auth.log',
        '/var/log/syslog',
        'C:\\Windows\\System32\\winevt\\Logs\\Security.evtx'
    ],
    'file_integrity': {
        'watch_paths': ['/etc', '/bin', '/usr/bin', 'C:\\Windows\\System32'],
        'check_interval': 300,
        'hash_algorithm': 'sha256'
    },
    'user_analytics': {
        'baseline_days': 30,
        'anomaly_threshold': 2.5,
        'risk_score_weights': {
            'login_time': 0.3,
            'file_access': 0.4,
            'network_activity': 0.3
        }
    },
    'compliance': {
        'regulations': ['PCI', 'HIPAA', 'GDPR'],
        'report_schedule': 'daily',
        'retention_days': 2555
    },
    'threat_rules': {
        'brute_force_threshold': 5,
        'privilege_escalation_keywords': ['sudo', 'su', 'runas', 'UAC'],
        'suspicious_processes': ['nc', 'netcat', 'powershell', 'cmd.exe'],
        'data_exfil_threshold': 100000000  # 100MB
    }
}

# Severity levels with colors
SEVERITY_COLORS = {
    'LOW': '\033[92m',      # Green
    'MEDIUM': '\033[93m',   # Yellow
    'HIGH': '\033[91m',     # Red
    'CRITICAL': '\033[94m', # Blue
    'RESET': '\033[0m'
}

# Logging setup
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('siem.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class DatabaseManager:
    """Database operations manager"""
    
    def __init__(self, db_path: str):
        self.db_path = db_path
        self.init_database()
    
    def init_database(self):
        """Initialize database schema"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Events table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                source TEXT,
                event_type TEXT,
                severity TEXT,
                message TEXT,
                src_ip TEXT,
                dst_ip TEXT,
                user_name TEXT,
                process_name TEXT,
                file_path TEXT,
                raw_log TEXT
            )
        ''')
        
        # User profiles table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS user_profiles (
                user_id TEXT PRIMARY KEY,
                baseline_activity TEXT,
                risk_score INTEGER DEFAULT 0,
                last_login DATETIME,
                login_count INTEGER DEFAULT 0,
                last_updated DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # File integrity table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS file_integrity (
                file_path TEXT PRIMARY KEY,
                hash_value TEXT,
                file_size INTEGER,
                last_modified DATETIME,
                permissions TEXT,
                first_seen DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # DNS queries table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS dns_queries (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                source_ip TEXT,
                query_domain TEXT,
                query_type TEXT,
                response_code INTEGER,
                reputation_score INTEGER DEFAULT 0
            )
        ''')
        
        # Compliance events table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS compliance_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                regulation TEXT,
                requirement TEXT,
                status TEXT,
                evidence TEXT,
                remediation TEXT
            )
        ''')
        
        # Threat intelligence table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS threat_intel (
                ioc TEXT PRIMARY KEY,
                ioc_type TEXT,
                threat_type TEXT,
                confidence INTEGER,
                first_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
                last_seen DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        conn.commit()
        conn.close()
    
    def execute_query(self, query: str, params: tuple = ()) -> List[tuple]:
        """Execute database query"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute(query, params)
            result = cursor.fetchall()
            conn.commit()
            conn.close()
            return result
        except Exception as e:
            logger.error(f"Database query error: {e}")
            return []
    
    def insert_event(self, event_data: Dict[str, Any]):
        """Insert security event"""
        query = '''
            INSERT INTO events (source, event_type, severity, message, src_ip, 
                              dst_ip, user_name, process_name, file_path, raw_log)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        '''
        params = (
            event_data.get('source', ''),
            event_data.get('event_type', ''),
            event_data.get('severity', ''),
            event_data.get('message', ''),
            event_data.get('src_ip', ''),
            event_data.get('dst_ip', ''),
            event_data.get('user_name', ''),
            event_data.get('process_name', ''),
            event_data.get('file_path', ''),
            event_data.get('raw_log', '')
        )
        self.execute_query(query, params)

class AdvancedThreatDetector:
    """Advanced threat detection engine"""
    
    def __init__(self, db_manager: DatabaseManager):
        self.db = db_manager
        self.connection_tracker = defaultdict(list)
        self.process_tracker = defaultdict(list)
        self.file_access_tracker = defaultdict(list)
    
    def detect_lateral_movement(self, src_ip: str, dst_ip: str, timestamp: datetime.datetime) -> Optional[Dict]:
        """Detect lateral movement patterns"""
        self.connection_tracker[src_ip].append((dst_ip, timestamp))
        
        # Check for rapid connections to multiple internal hosts
        recent_connections = [
            (dst, ts) for dst, ts in self.connection_tracker[src_ip]
            if (timestamp - ts).seconds < 300  # 5 minutes
        ]
        
        unique_destinations = set([dst for dst, _ in recent_connections])
        
        if len(unique_destinations) >= 3:
            return {
                'threat_type': 'lateral_movement',
                'severity': 'HIGH',
                'message': f'Lateral movement detected from {src_ip} to {len(unique_destinations)} hosts',
                'src_ip': src_ip,
                'evidence': f'Connections to: {", ".join(unique_destinations)}'
            }
        return None
    
    def detect_data_exfiltration(self, src_ip: str, bytes_transferred: int, timestamp: datetime.datetime) -> Optional[Dict]:
        """Detect data exfiltration attempts"""
        if bytes_transferred > CONFIG['threat_rules']['data_exfil_threshold']:
            return {
                'threat_type': 'data_exfiltration',
                'severity': 'CRITICAL',
                'message': f'Large data transfer detected: {bytes_transferred} bytes from {src_ip}',
                'src_ip': src_ip,
                'evidence': f'Transfer size: {bytes_transferred} bytes'
            }
        return None
    
    def detect_privilege_escalation(self, user: str, process: str, command: str) -> Optional[Dict]:
        """Detect privilege escalation attempts"""
        escalation_keywords = CONFIG['threat_rules']['privilege_escalation_keywords']
        
        if any(keyword in command.lower() for keyword in escalation_keywords):
            return {
                'threat_type': 'privilege_escalation',
                'severity': 'HIGH',
                'message': f'Privilege escalation attempt by {user} using {process}',
                'user_name': user,
                'process_name': process,
                'evidence': f'Command: {command}'
            }
        return None
    
    def detect_persistence_mechanisms(self, file_path: str, process: str) -> Optional[Dict]:
        """Detect persistence mechanism installation"""
        persistence_paths = [
            '/etc/crontab', '/etc/rc.local', '~/.bashrc', '~/.profile',
            'C:\\Windows\\System32\\Tasks', 'C:\\Users\\*\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup'
        ]
        
        if any(path in file_path for path in persistence_paths):
            return {
                'threat_type': 'persistence',
                'severity': 'MEDIUM',
                'message': f'Persistence mechanism detected: {file_path} modified by {process}',
                'file_path': file_path,
                'process_name': process,
                'evidence': f'Modified persistence file: {file_path}'
            }
        return None
    
    def behavioral_analysis(self, user: str, activity_data: Dict) -> Optional[Dict]:
        """Machine learning-based anomaly detection"""
        # Simple statistical anomaly detection
        baseline = self.get_user_baseline(user)
        if not baseline:
            return None
        
        anomaly_score = 0
        factors = []
        
        # Check login time anomaly
        current_hour = datetime.datetime.now().hour
        if abs(current_hour - baseline.get('avg_login_hour', 12)) > 4:
            anomaly_score += 1
            factors.append('unusual_login_time')
        
        # Check file access pattern
        if activity_data.get('files_accessed', 0) > baseline.get('avg_files_accessed', 0) * 2:
            anomaly_score += 1
            factors.append('excessive_file_access')
        
        # Check network activity
        if activity_data.get('network_connections', 0) > baseline.get('avg_connections', 0) * 2:
            anomaly_score += 1
            factors.append('excessive_network_activity')
        
        if anomaly_score >= 2:
            return {
                'threat_type': 'behavioral_anomaly',
                'severity': 'MEDIUM',
                'message': f'Behavioral anomaly detected for user {user}',
                'user_name': user,
                'evidence': f'Anomalous factors: {", ".join(factors)}'
            }
        return None
    
    def get_user_baseline(self, user: str) -> Dict:
        """Get user behavior baseline"""
        query = "SELECT baseline_activity FROM user_profiles WHERE user_id = ?"
        result = self.db.execute_query(query, (user,))
        
        if result:
            try:
                return json.loads(result[0][0] or '{}')
            except:
                return {}
        return {}

class FileIntegrityMonitor:
    """File integrity monitoring system"""
    
    def __init__(self, db_manager: DatabaseManager):
        self.db = db_manager
        self.watched_paths = CONFIG['file_integrity']['watch_paths']
        self.check_interval = CONFIG['file_integrity']['check_interval']
        self.file_hashes = {}
        self.running = False
    
    def calculate_file_hash(self, filepath: str) -> Optional[str]:
        """Calculate SHA-256 hash of file"""
        try:
            hash_algo = hashlib.sha256()
            with open(filepath, 'rb') as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    hash_algo.update(chunk)
            return hash_algo.hexdigest()
        except Exception as e:
            logger.error(f"Error calculating hash for {filepath}: {e}")
            return None
    
    def get_file_info(self, filepath: str) -> Dict:
        """Get file metadata"""
        try:
            stat = os.stat(filepath)
            return {
                'size': stat.st_size,
                'modified': datetime.datetime.fromtimestamp(stat.st_mtime),
                'permissions': oct(stat.st_mode)[-3:]
            }
        except Exception as e:
            logger.error(f"Error getting file info for {filepath}: {e}")
            return {}
    
    def baseline_system(self):
        """Create initial file integrity baseline"""
        logger.info("Creating file integrity baseline...")
        
        for watch_path in self.watched_paths:
            if not os.path.exists(watch_path):
                continue
                
            for root, dirs, files in os.walk(watch_path):
                for file in files:
                    filepath = os.path.join(root, file)
                    
                    if os.path.isfile(filepath):
                        file_hash = self.calculate_file_hash(filepath)
                        file_info = self.get_file_info(filepath)
                        
                        if file_hash and file_info:
                            query = '''
                                INSERT OR REPLACE INTO file_integrity 
                                (file_path, hash_value, file_size, last_modified, permissions)
                                VALUES (?, ?, ?, ?, ?)
                            '''
                            self.db.execute_query(query, (
                                filepath, file_hash, file_info['size'],
                                file_info['modified'], file_info['permissions']
                            ))
        
        logger.info("File integrity baseline created")
    
    def monitor_critical_files(self):
        """Monitor critical system files"""
        self.running = True
        
        while self.running:
            try:
                self.detect_file_changes()
                time.sleep(self.check_interval)
            except Exception as e:
                logger.error(f"File monitoring error: {e}")
                time.sleep(60)
    
    def detect_file_changes(self):
        """Detect unauthorized file modifications"""
        query = "SELECT file_path, hash_value, file_size FROM file_integrity"
        baseline_files = self.db.execute_query(query)
        
        for filepath, stored_hash, stored_size in baseline_files:
            if not os.path.exists(filepath):
                # File deleted
                event_data = {
                    'source': 'file_integrity',
                    'event_type': 'file_deleted',
                    'severity': 'HIGH',
                    'message': f'Critical file deleted: {filepath}',
                    'file_path': filepath
                }
                self.db.insert_event(event_data)
                continue
            
            current_hash = self.calculate_file_hash(filepath)
            current_info = self.get_file_info(filepath)
            
            if current_hash != stored_hash:
                # File modified
                event_data = {
                    'source': 'file_integrity',
                    'event_type': 'file_modified',
                    'severity': 'MEDIUM',
                    'message': f'Critical file modified: {filepath}',
                    'file_path': filepath
                }
                self.db.insert_event(event_data)
                
                # Update baseline
                query = '''
                    UPDATE file_integrity 
                    SET hash_value = ?, file_size = ?, last_modified = ?
                    WHERE file_path = ?
                '''
                self.db.execute_query(query, (
                    current_hash, current_info.get('size', 0),
                    current_info.get('modified', datetime.datetime.now()),
                    filepath
                ))

class DNSMonitor:
    """DNS monitoring and analysis"""
    
    def __init__(self, db_manager: DatabaseManager):
        self.db = db_manager
        self.suspicious_domains = set()
        self.dga_patterns = [
            r'^[a-z]{8,}\.com$',  # Long random strings
            r'^[0-9a-f]{32}\.com$',  # Hex strings
        ]
    
    def monitor_dns_queries(self, query_domain: str, source_ip: str, query_type: str = 'A'):
        """Monitor and log DNS queries"""
        reputation_score = self.check_domain_reputation(query_domain)
        
        query = '''
            INSERT INTO dns_queries (source_ip, query_domain, query_type, reputation_score)
            VALUES (?, ?, ?, ?)
        '''
        self.db.execute_query(query, (source_ip, query_domain, query_type, reputation_score))
        
        # Check for threats
        if self.detect_dns_tunneling(query_domain, source_ip):
            event_data = {
                'source': 'dns_monitor',
                'event_type': 'dns_tunneling',
                'severity': 'HIGH',
                'message': f'DNS tunneling detected: {query_domain}',
                'src_ip': source_ip
            }
            self.db.insert_event(event_data)
        
        if self.detect_dga_domains(query_domain):
            event_data = {
                'source': 'dns_monitor',
                'event_type': 'dga_domain',
                'severity': 'MEDIUM',
                'message': f'DGA domain detected: {query_domain}',
                'src_ip': source_ip
            }
            self.db.insert_event(event_data)
    
    def detect_dns_tunneling(self, domain: str, source_ip: str) -> bool:
        """Detect DNS tunneling attempts"""
        # Check for unusually long subdomains
        if len(domain) > 50:
            return True
        
        # Check for high frequency of queries from same IP
        query = '''
            SELECT COUNT(*) FROM dns_queries 
            WHERE source_ip = ? AND timestamp > datetime('now', '-1 minute')
        '''
        result = self.db.execute_query(query, (source_ip,))
        
        if result and result[0][0] > 10:
            return True
        
        return False
    
    def detect_dga_domains(self, domain: str) -> bool:
        """Detect Domain Generation Algorithm domains"""
        for pattern in self.dga_patterns:
            if re.match(pattern, domain):
                return True
        return False
    
    def check_domain_reputation(self, domain: str) -> int:
        """Check domain reputation (simplified)"""
        # Known malicious domains
        malicious_domains = {
            'malware.com': -100,
            'phishing.net': -90,
            'spam.org': -50
        }
        
        return malicious_domains.get(domain, 0)

class UserBehaviorAnalytics:
    """User behavior analytics engine"""
    
    def __init__(self, db_manager: DatabaseManager):
        self.db = db_manager
        self.user_sessions = defaultdict(dict)
    
    def profile_user_activity(self, user: str, activity_type: str, timestamp: datetime.datetime):
        """Build user activity profile"""
        if user not in self.user_sessions:
            self.user_sessions[user] = {
                'login_times': [],
                'file_accesses': [],
                'network_connections': [],
                'commands_executed': []
            }
        
        if activity_type == 'login':
            self.user_sessions[user]['login_times'].append(timestamp.hour)
        elif activity_type == 'file_access':
            self.user_sessions[user]['file_accesses'].append(timestamp)
        elif activity_type == 'network':
            self.user_sessions[user]['network_connections'].append(timestamp)
    
    def detect_anomalous_login_times(self, user: str, login_time: datetime.datetime) -> bool:
        """Detect unusual login hours"""
        query = '''
            SELECT strftime('%H', timestamp) as hour FROM events 
            WHERE user_name = ? AND event_type = 'login' 
            AND timestamp > datetime('now', '-30 days')
        '''
        result = self.db.execute_query(query, (user,))
        
        if not result:
            return False
        
        typical_hours = [int(row[0]) for row in result]
        current_hour = login_time.hour
        
        if typical_hours:
            avg_hour = statistics.mean(typical_hours)
            if abs(current_hour - avg_hour) > 4:
                return True
        
        return False
    
    def detect_unusual_file_access(self, user: str, file_path: str) -> bool:
        """Detect unusual file access patterns"""
        # Check if user typically accesses this type of file
        file_ext = os.path.splitext(file_path)[1]
        
        query = '''
            SELECT file_path FROM events 
            WHERE user_name = ? AND event_type = 'file_access'
            AND timestamp > datetime('now', '-30 days')
        '''
        result = self.db.execute_query(query, (user,))
        
        if not result:
            return True  # First time accessing any file
        
        user_file_types = set()
        for row in result:
            if row[0]:
                ext = os.path.splitext(row[0])[1]
                user_file_types.add(ext)
        
        return file_ext not in user_file_types
    
    def detect_account_abuse(self, user: str) -> Optional[Dict]:
        """Detect compromised account indicators"""
        query = '''
            SELECT COUNT(*) as login_count, 
                   COUNT(DISTINCT src_ip) as ip_count
            FROM events 
            WHERE user_name = ? AND event_type = 'login'
            AND timestamp > datetime('now', '-1 hour')
        '''
        result = self.db.execute_query(query, (user,))
        
        if result:
            login_count, ip_count = result[0]
            
            # Multiple IPs in short time
            if ip_count > 3:
                return {
                    'threat_type': 'account_abuse',
                    'severity': 'HIGH',
                    'message': f'Account {user} accessed from {ip_count} different IPs',
                    'user_name': user
                }
            
            # Excessive login attempts
            if login_count > 20:
                return {
                    'threat_type': 'account_abuse',
                    'severity': 'MEDIUM',
                    'message': f'Excessive login attempts for {user}: {login_count}',
                    'user_name': user
                }
        
        return None
    
    def calculate_risk_score(self, user: str) -> int:
        """Calculate user risk score"""
        risk_score = 0
        
        # Recent security events
        query = '''
            SELECT severity, COUNT(*) FROM events 
            WHERE user_name = ? AND timestamp > datetime('now', '-7 days')
            GROUP BY severity
        '''
        result = self.db.execute_query(query, (user,))
        
        severity_weights = {'LOW': 1, 'MEDIUM': 3, 'HIGH': 5, 'CRITICAL': 10}
        
        for severity, count in result:
            risk_score += severity_weights.get(severity, 0) * count
        
        return min(risk_score, 100)  # Cap at 100

class LogCorrelationEngine:
    """Advanced log correlation and analysis"""
    
    def __init__(self, db_manager: DatabaseManager):
        self.db = db_manager
        self.correlation_rules = self.load_correlation_rules()
        self.event_buffer = deque(maxlen=1000)
    
    def load_correlation_rules(self) -> List[Dict]:
        """Load correlation rules"""
        return [
            {
                'name': 'brute_force_attack',
                'events': ['failed_login', 'failed_login', 'successful_login'],
                'timeframe': 300,  # 5 minutes
                'severity': 'HIGH'
            },
            {
                'name': 'privilege_escalation_chain',
                'events': ['login', 'privilege_escalation', 'file_access'],
                'timeframe': 600,  # 10 minutes
                'severity': 'CRITICAL'
            },
            {
                'name': 'data_exfiltration_chain',
                'events': ['file_access', 'network_connection', 'data_transfer'],
                'timeframe': 900,  # 15 minutes
                'severity': 'CRITICAL'
            }
        ]
    
    def correlate_events(self, new_event: Dict):
        """Correlate incoming events"""
        self.event_buffer.append(new_event)
        
        for rule in self.correlation_rules:
            if self.match_correlation_rule(rule):
                self.generate_correlation_alert(rule, new_event)
    
    def match_correlation_rule(self, rule: Dict) -> bool:
        """Check if events match correlation rule"""
        required_events = rule['events']
        timeframe = rule['timeframe']
        current_time = datetime.datetime.now()
        
        matched_events = []
        
        for event in reversed(self.event_buffer):
            event_time = datetime.datetime.fromisoformat(event.get('timestamp', current_time.isoformat()))
            
            if (current_time - event_time).seconds > timeframe:
                break
            
            if event.get('event_type') in required_events:
                matched_events.append(event)
        
        # Check if we have all required event types
        matched_types = [e.get('event_type') for e in matched_events]
        return all(event_type in matched_types for event_type in required_events)
    
    def generate_correlation_alert(self, rule: Dict, trigger_event: Dict):
        """Generate correlation-based alert"""
        event_data = {
            'source': 'correlation_engine',
            'event_type': 'correlation_alert',
            'severity': rule['severity'],
            'message': f"Correlation rule triggered: {rule['name']}",
            'raw_log': json.dumps({
                'rule': rule['name'],
                'trigger_event': trigger_event
            })
        }
        self.db.insert_event(event_data)
    
    def detect_attack_chains(self) -> List[Dict]:
        """Identify multi-stage attack patterns"""
        attack_chains = []
        
        # Look for common attack patterns
        query = '''
            SELECT * FROM events 
            WHERE timestamp > datetime('now', '-1 hour')
            ORDER BY timestamp DESC
        '''
        recent_events = self.db.execute_query(query)
        
        # Group events by source IP
        events_by_ip = defaultdict(list)
        for event in recent_events:
            if event[6]:  # src_ip field
                events_by_ip[event[6]].append(event)
        
        for ip, events in events_by_ip.items():
            if len(events) >= 3:
                attack_chains.append({
                    'source_ip': ip,
                    'event_count': len(events),
                    'attack_stages': [e[3] for e in events],  # event_type
                    'severity': 'HIGH' if len(events) > 5 else 'MEDIUM'
                })
        
        return attack_chains
    
    def generate_timeline(self, incident_id: str) -> List[Dict]:
        """Generate attack timeline reconstruction"""
        query = '''
            SELECT timestamp, event_type, message, src_ip, user_name 
            FROM events 
            WHERE id = ? OR raw_log LIKE ?
            ORDER BY timestamp
        '''
        events = self.db.execute_query(query, (incident_id, f'%{incident_id}%'))
        
        timeline = []
        for event in events:
            timeline.append({
                'timestamp': event[0],
                'event_type': event[1],
                'message': event[2],
                'source_ip': event[3],
                'user': event[4]
            })
        
        return timeline

class ComplianceReporter:
    """Compliance reporting and audit functions"""
    
    def __init__(self, db_manager: DatabaseManager):
        self.db = db_manager
        self.regulations = CONFIG['compliance']['regulations']
    
    def generate_pci_report(self) -> Dict:
        """Generate PCI DSS compliance report"""
        report = {
            'regulation': 'PCI DSS',
            'generated_at': datetime.datetime.now().isoformat(),
            'requirements': {}
        }
        
        # Requirement 10: Log and monitor all access
        query = '''
            SELECT COUNT(*) FROM events 
            WHERE event_type IN ('login', 'file_access', 'admin_access')
            AND timestamp > datetime('now', '-30 days')
        '''
        result = self.db.execute_query(query)
        report['requirements']['10.1'] = {
            'description': 'Audit trails for all system components',
            'status': 'COMPLIANT' if result and result[0][0] > 0 else 'NON_COMPLIANT',
            'evidence': f"Logged {result[0][0] if result else 0} access events in last 30 days"
        }
        
        return report
    
    def generate_hipaa_report(self) -> Dict:
        """Generate HIPAA compliance report"""
        report = {
            'regulation': 'HIPAA',
            'generated_at': datetime.datetime.now().isoformat(),
            'requirements': {}
        }
        
        # Access control monitoring
        query = '''
            SELECT COUNT(*) FROM events 
            WHERE event_type = 'unauthorized_access'
            AND timestamp > datetime('now', '-30 days')
        '''
        result = self.db.execute_query(query)
        report['requirements']['164.312'] = {
            'description': 'Access control safeguards',
            'status': 'COMPLIANT' if result and result[0][0] == 0 else 'NON_COMPLIANT',
            'evidence': f"Detected {result[0][0] if result else 0} unauthorized access attempts"
        }
        
        return report
    
    def generate_gdpr_report(self) -> Dict:
        """Generate GDPR compliance report"""
        report = {
            'regulation': 'GDPR',
            'generated_at': datetime.datetime.now().isoformat(),
            'requirements': {}
        }
        
        # Data breach notification
        query = '''
            SELECT COUNT(*) FROM events 
            WHERE event_type IN ('data_breach', 'unauthorized_access', 'data_exfiltration')
            AND timestamp > datetime('now', '-30 days')
        '''
        result = self.db.execute_query(query)
        report['requirements']['33'] = {
            'description': 'Breach notification requirements',
            'status': 'ATTENTION_REQUIRED' if result and result[0][0] > 0 else 'COMPLIANT',
            'evidence': f"Detected {result[0][0] if result else 0} potential breach events"
        }
        
        return report
    
    def export_audit_logs(self, format_type: str = 'json', days: int = 30) -> str:
        """Export audit logs in various formats"""
        query = '''
            SELECT * FROM events 
            WHERE timestamp > datetime('now', '-{} days')
            ORDER BY timestamp DESC
        '''.format(days)
        
        events = self.db.execute_query(query)
        
        if format_type == 'json':
            export_data = []
            for event in events:
                export_data.append({
                    'id': event[0],
                    'timestamp': event[1],
                    'source': event[2],
                    'event_type': event[3],
                    'severity': event[4],
                    'message': event[5],
                    'src_ip': event[6],
                    'dst_ip': event[7],
                    'user_name': event[8],
                    'process_name': event[9],
                    'file_path': event[10],
                    'raw_log': event[11]
                })
            return json.dumps(export_data, indent=2)
        
        elif format_type == 'csv':
            csv_data = "ID,Timestamp,Source,Event Type,Severity,Message,Src IP,Dst IP,User,Process,File Path\n"
            for event in events:
                csv_data += ','.join([str(field or '') for field in event[:11]]) + '\n'
            return csv_data
        
        return str(events)
    
    def schedule_reports(self):
        """Schedule automated report generation"""
        def generate_daily_reports():
            while True:
                try:
                    # Generate compliance reports
                    pci_report = self.generate_pci_report()
                    hipaa_report = self.generate_hipaa_report()
                    gdpr_report = self.generate_gdpr_report()
                    
                    # Store reports
                    reports = [pci_report, hipaa_report, gdpr_report]
                    for report in reports:
                        query = '''
                            INSERT INTO compliance_events (regulation, requirement, status, evidence)
                            VALUES (?, ?, ?, ?)
                        '''
                        self.db.execute_query(query, (
                            report['regulation'],
                            'daily_report',
                            'GENERATED',
                            json.dumps(report)
                        ))
                    
                    logger.info("Daily compliance reports generated")
                    time.sleep(86400)  # 24 hours
                    
                except Exception as e:
                    logger.error(f"Report generation error: {e}")
                    time.sleep(3600)  # Retry in 1 hour
        
        thread = threading.Thread(target=generate_daily_reports, daemon=True)
        thread.start()

class LogParser:
    """Log parsing and event extraction"""
    
    def __init__(self, db_manager: DatabaseManager):
        self.db = db_manager
        self.parsers = {
            'syslog': self.parse_syslog,
            'auth': self.parse_auth_log,
            'windows_security': self.parse_windows_security
        }
    
    def parse_log_line(self, log_line: str, source: str) -> Optional[Dict]:
        """Parse individual log line"""
        try:
            if 'auth.log' in source or 'secure' in source:
                return self.parse_auth_log(log_line)
            elif 'syslog' in source:
                return self.parse_syslog(log_line)
            elif 'Security.evtx' in source:
                return self.parse_windows_security(log_line)
            else:
                return self.parse_generic_log(log_line)
        except Exception as e:
            logger.error(f"Log parsing error: {e}")
            return None
    
    def parse_auth_log(self, log_line: str) -> Optional[Dict]:
        """Parse authentication logs"""
        patterns = {
            'failed_login': r'Failed password for (\w+) from ([\d.]+)',
            'successful_login': r'Accepted password for (\w+) from ([\d.]+)',
            'sudo_usage': r'sudo:\s+(\w+) : TTY=\w+ ; PWD=.*? ; USER=(\w+) ; COMMAND=(.*)',
            'su_usage': r'su: \(to (\w+)\) (\w+) on'
        }
        
        for event_type, pattern in patterns.items():
            match = re.search(pattern, log_line)
            if match:
                if event_type == 'failed_login':
                    return {
                        'event_type': 'failed_login',
                        'severity': 'MEDIUM',
                        'user_name': match.group(1),
                        'src_ip': match.group(2),
                        'message': f"Failed login attempt for {match.group(1)} from {match.group(2)}",
                        'raw_log': log_line
                    }
                elif event_type == 'successful_login':
                    return {
                        'event_type': 'successful_login',
                        'severity': 'LOW',
                        'user_name': match.group(1),
                        'src_ip': match.group(2),
                        'message': f"Successful login for {match.group(1)} from {match.group(2)}",
                        'raw_log': log_line
                    }
                elif event_type == 'sudo_usage':
                    return {
                        'event_type': 'privilege_escalation',
                        'severity': 'MEDIUM',
                        'user_name': match.group(1),
                        'message': f"Sudo command executed: {match.group(3)}",
                        'raw_log': log_line
                    }
        
        return None
    
    def parse_syslog(self, log_line: str) -> Optional[Dict]:
        """Parse system logs"""
        # Process start/stop patterns
        process_pattern = r'(\w+)\[(\d+)\]: (.*)'
        match = re.search(process_pattern, log_line)
        
        if match:
            process_name = match.group(1)
            pid = match.group(2)
            message = match.group(3)
            
            # Check for suspicious processes
            if process_name in CONFIG['threat_rules']['suspicious_processes']:
                return {
                    'event_type': 'suspicious_process',
                    'severity': 'HIGH',
                    'process_name': process_name,
                    'message': f"Suspicious process started: {process_name} (PID: {pid})",
                    'raw_log': log_line
                }
        
        return None
    
    def parse_windows_security(self, log_line: str) -> Optional[Dict]:
        """Parse Windows Security Event Log"""
        # Simplified Windows event parsing
        if 'Event ID: 4624' in log_line:  # Successful logon
            return {
                'event_type': 'successful_login',
                'severity': 'LOW',
                'message': 'Windows successful logon',
                'raw_log': log_line
            }
        elif 'Event ID: 4625' in log_line:  # Failed logon
            return {
                'event_type': 'failed_login',
                'severity': 'MEDIUM',
                'message': 'Windows failed logon attempt',
                'raw_log': log_line
            }
        elif 'Event ID: 4648' in log_line:  # Explicit credential use
            return {
                'event_type': 'privilege_escalation',
                'severity': 'MEDIUM',
                'message': 'Windows explicit credential use',
                'raw_log': log_line
            }
        
        return None
    
    def parse_generic_log(self, log_line: str) -> Optional[Dict]:
        """Parse generic log format"""
        return {
            'event_type': 'generic',
            'severity': 'LOW',
            'message': log_line[:100],  # First 100 chars
            'raw_log': log_line
        }

class NetworkMonitor:
    """Network traffic monitoring"""
    
    def __init__(self, db_manager: DatabaseManager):
        self.db = db_manager
        self.connection_stats = defaultdict(lambda: {'bytes_in': 0, 'bytes_out': 0, 'connections': 0})
    
    def monitor_network_connections(self):
        """Monitor active network connections"""
        try:
            connections = psutil.net_connections(kind='inet')
            
            for conn in connections:
                if conn.status == 'ESTABLISHED':
                    local_addr = f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else "unknown"
                    remote_addr = f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "unknown"
                    
                    # Track connection statistics
                    self.connection_stats[local_addr]['connections'] += 1
                    
                    # Check for suspicious connections
                    if self.is_suspicious_connection(conn):
                        event_data = {
                            'source': 'network_monitor',
                            'event_type': 'suspicious_connection',
                            'severity': 'MEDIUM',
                            'message': f"Suspicious network connection: {local_addr} -> {remote_addr}",
                            'src_ip': conn.laddr.ip if conn.laddr else '',
                            'dst_ip': conn.raddr.ip if conn.raddr else ''
                        }
                        self.db.insert_event(event_data)
        
        except Exception as e:
            logger.error(f"Network monitoring error: {e}")
    
    def is_suspicious_connection(self, conn) -> bool:
        """Check if connection is suspicious"""
        if not conn.raddr:
            return False
        
        # Check for connections to suspicious ports
        suspicious_ports = [4444, 5555, 6666, 7777, 8080, 9999]
        if conn.raddr.port in suspicious_ports:
            return True
        
        # Check for connections to private IP ranges from public IPs
        remote_ip = conn.raddr.ip
        if self.is_private_ip(remote_ip) and conn.laddr and not self.is_private_ip(conn.laddr.ip):
            return True
        
        return False
    
    def is_private_ip(self, ip: str) -> bool:
        """Check if IP is in private range"""
        private_ranges = [
            '10.0.0.0/8',
            '172.16.0.0/12',
            '192.168.0.0/16',
            '127.0.0.0/8'
        ]
        
        try:
            import ipaddress
            ip_obj = ipaddress.ip_address(ip)
            return any(ip_obj in ipaddress.ip_network(range_) for range_ in private_ranges)
        except:
            return False
    
    def get_network_statistics(self) -> Dict:
        """Get network usage statistics"""
        try:
            net_io = psutil.net_io_counters()
            return {
                'bytes_sent': net_io.bytes_sent,
                'bytes_recv': net_io.bytes_recv,
                'packets_sent': net_io.packets_sent,
                'packets_recv': net_io.packets_recv,
                'connections': len(psutil.net_connections())
            }
        except Exception as e:
            logger.error(f"Network statistics error: {e}")
            return {}

class WebInterface:
    """Web-based dashboard interface"""
    
    def __init__(self, db_manager: DatabaseManager):
        self.db = db_manager
    
    def get_dashboard_data(self) -> Dict:
        """Get dashboard statistics"""
        data = {}
        
        # Total events
        query = "SELECT COUNT(*) FROM events"
        result = self.db.execute_query(query)
        data['total_events'] = result[0][0] if result else 0
        
        # Threats by severity
        query = '''
            SELECT severity, COUNT(*) FROM events 
            WHERE timestamp > datetime('now', '-24 hours')
            GROUP BY severity
        '''
        result = self.db.execute_query(query)
        data['threats'] = {row[0]: row[1] for row in result} if result else {}
        
        # Active users
        query = '''
            SELECT COUNT(DISTINCT user_name) FROM events 
            WHERE timestamp > datetime('now', '-24 hours') AND user_name IS NOT NULL
        '''
        result = self.db.execute_query(query)
        data['active_users'] = result[0][0] if result else 0
        
        # Recent events
        query = '''
            SELECT timestamp, event_type, severity, message, src_ip, user_name 
            FROM events 
            ORDER BY timestamp DESC 
            LIMIT 20
        '''
        result = self.db.execute_query(query)
        data['recent_events'] = [
            {
                'timestamp': row[0],
                'type': row[1],
                'severity': row[2],
                'message': row[3],
                'src_ip': row[4],
                'user': row[5]
            }
            for row in result
        ] if result else []
        
        return data
    
    def format_severity(self, severity: str) -> str:
        """Format severity with color codes"""
        color = SEVERITY_COLORS.get(severity, '')
        reset = SEVERITY_COLORS['RESET']
        return f"{color}{severity}{reset}"

class SIEMRequestHandler(BaseHTTPRequestHandler):
    """HTTP request handler for web interface"""
    
    def __init__(self, *args, siem_system=None, **kwargs):
        self.siem = siem_system
        super().__init__(*args, **kwargs)
    
    def do_GET(self):
        """Handle GET requests"""
        parsed_path = urlparse(self.path)
        
        if parsed_path.path == '/' or parsed_path.path == '/dashboard':
            self.serve_dashboard()
        elif parsed_path.path == '/api/events':
            self.serve_api_events()
        elif parsed_path.path == '/api/stats':
            self.serve_api_stats()
        else:
            self.send_error(404)
    
    def serve_dashboard(self):
        """Serve main dashboard"""
        dashboard_data = self.siem.web_interface.get_dashboard_data()
        
        # Generate event list HTML
        event_list_html = ""
        for event in dashboard_data['recent_events']:
            severity_class = event['severity'].lower()
            event_list_html += f'''
                <div class="event {severity_class}">
                    <span class="time">{event['timestamp'][:19]}</span>
                    <span class="type">{event['type']}</span>
                    <span class="severity">{event['severity']}</span>
                    <span class="message">{event['message'][:80]}...</span>
                </div>
            '''
        
        # Calculate threat counts
        total_threats = sum(dashboard_data['threats'].values())
        
        html_content = f'''<!DOCTYPE html>
<html>
<head>
    <title>SIEM DASHBOARD</title>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <style>
        * {{ margin:0; padding:0; box-sizing:border-box; font-family:monospace; }}
        body {{ background:#000; color:#fff; padding:20px; min-height:100vh; }}
        h1 {{ color:#fff; margin-bottom:20px; text-align:center; font-size:24px; }}
        .grid {{ display:grid; grid-template-columns:repeat(4,1fr); gap:20px; margin-bottom:20px; }}
        .card {{ background:#333; padding:15px; border:1px solid #666; text-align:center; }}
        .card h3 {{ color:#999; font-size:12px; margin-bottom:5px; }}
        .card h2 {{ color:#ccc; font-size:18px; }}
        .events {{ background:#333; padding:15px; border:1px solid #666; max-height:500px; overflow-y:auto; }}
        .events h3 {{ color:#999; font-size:14px; margin-bottom:10px; }}
        .event {{ margin:5px 0; padding:8px; background:#000; border-left:3px solid #999; font-size:12px; }}
        .event.low {{ border-left-color:#00ff00; }}
        .event.medium {{ border-left-color:#ffff00; }}
        .event.high {{ border-left-color:#ff0000; }}
        .event.critical {{ border-left-color:#0000ff; }}
        .event span {{ display:inline-block; margin-right:10px; }}
        .time {{ width:130px; color:#999; }}
        .type {{ width:120px; color:#ccc; }}
        .severity {{ width:80px; font-weight:bold; }}
        .message {{ color:#fff; }}
        .status {{ color:#00ff00; }}
    </style>
</head>
<body>
    <h1>SIEM DASHBOARD</h1>
    <div class="grid">
        <div class="card">
            <h3>TOTAL EVENTS</h3>
            <h2>{dashboard_data['total_events']}</h2>
        </div>
        <div class="card">
            <h3>THREATS (24H)</h3>
            <h2>{total_threats}</h2>
        </div>
        <div class="card">
            <h3>ACTIVE USERS</h3>
            <h2>{dashboard_data['active_users']}</h2>
        </div>
        <div class="card">
            <h3>STATUS</h3>
            <h2 class="status">ONLINE</h2>
        </div>
    </div>
    <div class="events">
        <h3>RECENT SECURITY EVENTS</h3>
        {event_list_html if event_list_html else '<div class="event">No recent events</div>'}
    </div>
    <script>
        setInterval(function() {{
            location.reload();
        }}, 30000);
    </script>
</body>
</html>'''
        
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()
        self.wfile.write(html_content.encode())
    
    def serve_api_events(self):
        """Serve events API"""
        query_params = parse_qs(urlparse(self.path).query)
        limit = int(query_params.get('limit', [100])[0])
        
        query = f'''
            SELECT timestamp, event_type, severity, message, src_ip, user_name 
            FROM events 
            ORDER BY timestamp DESC 
            LIMIT {limit}
        '''
        result = self.siem.db.execute_query(query)
        
        events = [
            {
                'timestamp': row[0],
                'type': row[1],
                'severity': row[2],
                'message': row[3],
                'src_ip': row[4],
                'user': row[5]
            }
            for row in result
        ]
        
        self.send_response(200)
        self.send_header('Content-type', 'application/json')
        self.end_headers()
        self.wfile.write(json.dumps(events).encode())
    
    def serve_api_stats(self):
        """Serve statistics API"""
        stats = self.siem.web_interface.get_dashboard_data()
        
        self.send_response(200)
        self.send_header('Content-type', 'application/json')
        self.end_headers()
        self.wfile.write(json.dumps(stats).encode())

class EnhancedSIEMSystem:
    """Main SIEM system orchestrator"""
    
    def __init__(self):
        self.db = DatabaseManager(CONFIG['database'])
        self.threat_detector = AdvancedThreatDetector(self.db)
        self.file_monitor = FileIntegrityMonitor(self.db)
        self.dns_monitor = DNSMonitor(self.db)
        self.user_analytics = UserBehaviorAnalytics(self.db)
        self.correlation_engine = LogCorrelationEngine(self.db)
        self.compliance_reporter = ComplianceReporter(self.db)
        self.log_parser = LogParser(self.db)
        self.network_monitor = NetworkMonitor(self.db)
        self.web_interface = WebInterface(self.db)
        
        self.running = False
        self.threads = []
    
    def start(self):
        """Start all SIEM components"""
        logger.info("Starting Enhanced SIEM System...")
        self.running = True
        
        # Initialize file integrity baseline
        if not os.path.exists('baseline_created.flag'):
            self.file_monitor.baseline_system()
            open('baseline_created.flag', 'w').close()
        
        # Start monitoring threads
        threads = [
            threading.Thread(target=self.monitor_logs, daemon=True),
            threading.Thread(target=self.file_monitor.monitor_critical_files, daemon=True),
            threading.Thread(target=self.monitor_network, daemon=True),
            threading.Thread(target=self.process_threat_detection, daemon=True)
        ]
        
        for thread in threads:
            thread.start()
            self.threads.append(thread)
        
        # Start compliance reporting
        self.compliance_reporter.schedule_reports()
        
        # Start web interface
        self.start_web_server()
    
    def monitor_logs(self):
        """Monitor log files for security events"""
        processed_lines = {}
        
        while self.running:
            try:
                for log_source in CONFIG['log_sources']:
                    if os.path.exists(log_source):
                        self.process_log_file(log_source, processed_lines)
                
                time.sleep(5)  # Check every 5 seconds
                
            except Exception as e:
                logger.error(f"Log monitoring error: {e}")
                time.sleep(30)
    
    def process_log_file(self, log_file: str, processed_lines: Dict):
        """Process individual log file"""
        try:
            with open(log_file, 'r', encoding='utf-8', errors='ignore') as f:
                if log_file not in processed_lines:
                    # Skip to end for new files
                    f.seek(0, 2)
                    processed_lines[log_file] = f.tell()
                else:
                    f.seek(processed_lines[log_file])
                
                for line in f:
                    line = line.strip()
                    if line:
                        parsed_event = self.log_parser.parse_log_line(line, log_file)
                        if parsed_event:
                            parsed_event['source'] = os.path.basename(log_file)
                            self.db.insert_event(parsed_event)
                            self.correlation_engine.correlate_events(parsed_event)
                
                processed_lines[log_file] = f.tell()
                
        except Exception as e:
            logger.error(f"Error processing log file {log_file}: {e}")
    
    def monitor_network(self):
        """Monitor network activity"""
        while self.running:
            try:
                self.network_monitor.monitor_network_connections()
                time.sleep(60)  # Check every minute
            except Exception as e:
                logger.error(f"Network monitoring error: {e}")
                time.sleep(60)
    
    def process_threat_detection(self):
        """Process advanced threat detection"""
        while self.running:
            try:
                # Get recent events for analysis
                query = '''
                    SELECT * FROM events 
                    WHERE timestamp > datetime('now', '-1 hour')
                    ORDER BY timestamp DESC
                '''
                recent_events = self.db.execute_query(query)
                
                for event in recent_events:
                    self.analyze_event_for_threats(event)
                
                time.sleep(300)  # Analyze every 5 minutes
                
            except Exception as e:
                logger.error(f"Threat detection error: {e}")
                time.sleep(300)
    
    def analyze_event_for_threats(self, event):
        """Analyze individual event for threats"""
        try:
            event_data = {
                'timestamp': event[1],
                'event_type': event[3],
                'src_ip': event[6],
                'user_name': event[8],
                'process_name': event[9],
                'file_path': event[10]
            }
            
            # Check for various threat types
            threats = []
            
            if event_data['src_ip'] and event_data['event_type'] == 'network_connection':
                threat = self.threat_detector.detect_lateral_movement(
                    event_data['src_ip'], 
                    event[7],  # dst_ip
                    datetime.datetime.fromisoformat(event_data['timestamp'])
                )
                if threat:
                    threats.append(threat)
            
            if event_data['user_name'] and event_data['process_name']:
                threat = self.threat_detector.detect_privilege_escalation(
                    event_data['user_name'],
                    event_data['process_name'],
                    event[5]  # message
                )
                if threat:
                    threats.append(threat)
            
            # Insert detected threats as new events
            for threat in threats:
                threat['source'] = 'threat_detector'
                self.db.insert_event(threat)
                
        except Exception as e:
            logger.error(f"Event analysis error: {e}")
    
    def start_web_server(self):
        """Start web interface server"""
        def create_handler(*args, **kwargs):
            return SIEMRequestHandler(*args, siem_system=self, **kwargs)
        
        try:
            server = HTTPServer(('0.0.0.0', CONFIG['web_port']), create_handler)
            logger.info(f"Web interface started on port {CONFIG['web_port']}")
            
            def run_server():
                server.serve_forever()
            
            server_thread = threading.Thread(target=run_server, daemon=True)
            server_thread.start()
            self.threads.append(server_thread)
            
        except Exception as e:
            logger.error(f"Web server startup error: {e}")
    
    def stop(self):
        """Stop SIEM system"""
        logger.info("Stopping SIEM system...")
        self.running = False
        self.file_monitor.running = False
        
        # Wait for threads to finish
        for thread in self.threads:
            if thread.is_alive():
                thread.join(timeout=5)
    
    def get_system_status(self) -> Dict:
        """Get system status information"""
        return {
            'running': self.running,
            'threads_active': len([t for t in self.threads if t.is_alive()]),
            'database_status': 'connected' if os.path.exists(CONFIG['database']) else 'disconnected',
            'web_interface': f"http://localhost:{CONFIG['web_port']}",
            'last_update': datetime.datetime.now().isoformat()
        }

def main():
    """Main entry point"""
    print(f"{SEVERITY_COLORS['CRITICAL']}Enhanced SIEM System v2.0{SEVERITY_COLORS['RESET']}")
    print("=" * 50)
    
    # Initialize SIEM system
    siem = EnhancedSIEMSystem()
    
    try:
        # Start SIEM
        siem.start()
        
        # Print status
        status = siem.get_system_status()
        print(f"Status: {SEVERITY_COLORS['LOW']}RUNNING{SEVERITY_COLORS['RESET']}")
        print(f"Web Interface: {status['web_interface']}")
        print(f"Database: {status['database_status']}")
        print(f"Active Threads: {status['threads_active']}")
        print("\nPress Ctrl+C to stop...")
        
        # Keep main thread alive
        while True:
            time.sleep(60)
            # Print periodic status
            current_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            print(f"[{current_time}] SIEM System running - {len(siem.threads)} active threads")
            
    except KeyboardInterrupt:
        print("\nShutdown requested...")
        siem.stop()
        print("SIEM System stopped.")
    except Exception as e:
        logger.error(f"System error: {e}")
        siem.stop()

if __name__ == "__main__":
    main()