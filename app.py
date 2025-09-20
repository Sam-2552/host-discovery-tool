#!/usr/bin/env python3
"""
Host Discovery Tool with Nmap
A web-based tool for performing host discovery and port scanning with progressive port ranges.
"""

import os
import json
import subprocess
import threading
import time
import tempfile
import csv
import io
import sqlite3
import uuid
import re
from datetime import datetime
from flask import Flask, render_template, request, jsonify, session, send_file
from flask_socketio import SocketIO, emit, join_room, leave_room
import nmap

app = Flask(__name__)
app.config['SECRET_KEY'] = 'host_discovery_secret_key'
socketio = SocketIO(app, cors_allowed_origins="*")

# Database setup
DB_PATH = 'scan_sessions.db'
DOWNLOADS_DIR = 'downloads'

def sanitize_filename(filename):
    """Convert scan name to safe directory name"""
    # Remove or replace invalid characters
    safe_name = re.sub(r'[<>:"/\\|?*]', '_', filename)
    # Remove leading/trailing spaces and dots
    safe_name = safe_name.strip(' .')
    # Limit length
    safe_name = safe_name[:50]
    # Ensure it's not empty
    if not safe_name:
        safe_name = 'unnamed_scan'
    return safe_name

def get_scan_download_dir(scan_name):
    """Get the download directory for a scan"""
    safe_name = sanitize_filename(scan_name)
    scan_dir = os.path.join(DOWNLOADS_DIR, safe_name)
    os.makedirs(scan_dir, exist_ok=True)
    return scan_dir

def save_ip_list_file(scan_name, ip_list, scan_type):
    """Save IP list to scan directory"""
    if not ip_list or not ip_list.strip():
        return None
    
    scan_dir = get_scan_download_dir(scan_name)
    filename = f'{scan_type}_ips.txt'
    filepath = os.path.join(scan_dir, filename)
    
    with open(filepath, 'w') as f:
        f.write(ip_list)
    
    return filepath

def init_db():
    """Initialize the SQLite database with required tables"""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    # Create sessions table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS scan_sessions (
            session_id TEXT PRIMARY KEY,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # Create scans table (multiple scans per session)
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS scans (
            scan_id TEXT PRIMARY KEY,
            session_id TEXT,
            scan_name TEXT,
            target TEXT,
            ip_list TEXT,
            status TEXT DEFAULT 'idle',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            started_at TIMESTAMP,
            completed_at TIMESTAMP,
            FOREIGN KEY (session_id) REFERENCES scan_sessions (session_id)
        )
    ''')
    
    # Create scan_results table (results for each scan)
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS scan_results (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id TEXT,
            session_id TEXT,
            scan_status TEXT,
            current_target TEXT,
            current_scan_type TEXT,
            start_time TIMESTAMP,
            total_hosts INTEGER,
            ping_hosts TEXT,
            port_hosts TEXT,
            firewall_suspected TEXT,
            FOREIGN KEY (scan_id) REFERENCES scans (scan_id),
            FOREIGN KEY (session_id) REFERENCES scan_sessions (session_id)
        )
    ''')
    
    # Create scan_logs table (log entries for each scan)
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS scan_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id TEXT,
            session_id TEXT,
            log_type TEXT,
            message TEXT,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (scan_id) REFERENCES scans (scan_id),
            FOREIGN KEY (session_id) REFERENCES scan_sessions (session_id)
        )
    ''')
    
    conn.commit()
    conn.close()

def get_or_create_session_id():
    """Get or create a session ID for the current user"""
    if 'session_id' not in session:
        session['session_id'] = str(uuid.uuid4())
    return session['session_id']

def create_scan(session_id, scan_name, target, ip_list):
    """Create a new scan and return scan_id"""
    scan_id = str(uuid.uuid4())
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    # Ensure session exists
    cursor.execute('''
        INSERT OR IGNORE INTO scan_sessions (session_id) VALUES (?)
    ''', (session_id,))
    
    # Create new scan
    cursor.execute('''
        INSERT INTO scans (scan_id, session_id, scan_name, target, ip_list, status, started_at)
        VALUES (?, ?, ?, ?, ?, 'running', CURRENT_TIMESTAMP)
    ''', (scan_id, session_id, scan_name, target, ip_list))
    
    conn.commit()
    conn.close()
    return scan_id

def get_scan_results(scan_id):
    """Get scan results for a specific scan"""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    cursor.execute('''
        SELECT scan_status, current_target, current_scan_type, start_time, total_hosts, ping_hosts, port_hosts, firewall_suspected
        FROM scan_results WHERE scan_id = ? ORDER BY id DESC LIMIT 1
    ''', (scan_id,))
    
    result = cursor.fetchone()
    conn.close()
    
    if result:
        try:
            start_time = datetime.fromisoformat(result[3]) if result[3] else None
        except (ValueError, TypeError):
            # Handle invalid datetime format
            start_time = None
            
        return {
            'scan_status': result[0],
            'current_target': result[1],
            'current_scan_type': result[2],
            'start_time': start_time,
            'total_hosts': result[4],
            'ping_hosts': set(json.loads(result[5])) if result[5] else set(),
            'port_hosts': json.loads(result[6]) if result[6] else {},
            'firewall_suspected': set(json.loads(result[7])) if result[7] else set()
        }
    else:
        return {
            'ping_hosts': set(),
            'port_hosts': {},
            'scan_status': 'idle',
            'current_target': '',
            'current_scan_type': '',
            'start_time': None,
            'total_hosts': 0,
            'firewall_suspected': set()
        }

def get_session_scans(session_id):
    """Get all scans for a session"""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    cursor.execute('''
        SELECT scan_id, scan_name, target, ip_list, status, created_at, started_at, completed_at
        FROM scans WHERE session_id = ? ORDER BY created_at DESC
    ''', (session_id,))
    
    scans = cursor.fetchall()
    conn.close()
    
    return [{
        'scan_id': scan[0],
        'scan_name': scan[1],
        'target': scan[2],
        'ip_list': scan[3],
        'status': scan[4],
        'created_at': scan[5],
        'started_at': scan[6],
        'completed_at': scan[7]
    } for scan in scans]

def save_scan_results(scan_id, session_id, scan_data):
    """Save scan results to database"""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    # Ensure session exists
    cursor.execute('''
        INSERT OR IGNORE INTO scan_sessions (session_id) VALUES (?)
    ''', (session_id,))
    
    # Save scan results
    cursor.execute('''
        INSERT INTO scan_results (
            scan_id, session_id, scan_status, current_target, current_scan_type,
            start_time, total_hosts, ping_hosts, port_hosts, firewall_suspected
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ''', (
        scan_id,
        session_id,
        scan_data['scan_status'],
        scan_data['current_target'],
        scan_data['current_scan_type'],
        scan_data['start_time'].isoformat() if scan_data['start_time'] else None,
        scan_data['total_hosts'],
        json.dumps(list(scan_data['ping_hosts'])),
        json.dumps(scan_data['port_hosts']),
        json.dumps(list(scan_data['firewall_suspected']))
    ))
    
    conn.commit()
    conn.close()

def update_scan_status(scan_id, status):
    """Update scan status"""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    if status == 'completed':
        cursor.execute('''
            UPDATE scans SET status = ?, completed_at = CURRENT_TIMESTAMP WHERE scan_id = ?
        ''', (status, scan_id))
    else:
        cursor.execute('''
            UPDATE scans SET status = ? WHERE scan_id = ?
        ''', (status, scan_id))
    
    conn.commit()
    conn.close()

def cleanup_old_data():
    """Clean up any old data that might cause issues"""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    # Drop old scan_results table if it exists with wrong schema
    try:
        cursor.execute('DROP TABLE IF EXISTS old_scan_results')
        cursor.execute('ALTER TABLE scan_results RENAME TO old_scan_results')
    except:
        pass
    
    # Recreate scan_results table with correct schema
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS scan_results (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id TEXT,
            session_id TEXT,
            scan_status TEXT,
            current_target TEXT,
            current_scan_type TEXT,
            start_time TIMESTAMP,
            total_hosts INTEGER,
            ping_hosts TEXT,
            port_hosts TEXT,
            firewall_suspected TEXT,
            FOREIGN KEY (scan_id) REFERENCES scans (scan_id),
            FOREIGN KEY (session_id) REFERENCES scan_sessions (session_id)
        )
    ''')
    
    # Recreate scans table with scan_name field
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS scans_new (
            scan_id TEXT PRIMARY KEY,
            session_id TEXT,
            scan_name TEXT,
            target TEXT,
            ip_list TEXT,
            status TEXT DEFAULT 'idle',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            started_at TIMESTAMP,
            completed_at TIMESTAMP,
            FOREIGN KEY (session_id) REFERENCES scan_sessions (session_id)
        )
    ''')
    
    # Copy data from old scans table to new one
    cursor.execute('''
        INSERT INTO scans_new (scan_id, session_id, scan_name, target, ip_list, status, created_at, started_at, completed_at)
        SELECT scan_id, session_id, 
               CASE 
                   WHEN target = 'IP List' THEN 'IP List Scan - ' || datetime(created_at, 'localtime')
                   ELSE target || ' - ' || datetime(created_at, 'localtime')
               END as scan_name,
               target, ip_list, status, created_at, started_at, completed_at
        FROM scans
    ''')
    
    # Drop old table and rename new one
    cursor.execute('DROP TABLE scans')
    cursor.execute('ALTER TABLE scans_new RENAME TO scans')
    
    # Drop old table
    cursor.execute('DROP TABLE IF EXISTS old_scan_results')
    
    conn.commit()
    conn.close()

def save_scan_log(scan_id, session_id, log_type, message):
    """Save a log entry to the database"""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    cursor.execute('''
        INSERT INTO scan_logs (scan_id, session_id, log_type, message)
        VALUES (?, ?, ?, ?)
    ''', (scan_id, session_id, log_type, message))
    
    conn.commit()
    conn.close()

def get_scan_logs(scan_id):
    """Get all log entries for a specific scan"""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    cursor.execute('''
        SELECT log_type, message, timestamp
        FROM scan_logs WHERE scan_id = ?
        ORDER BY timestamp ASC
    ''', (scan_id,))
    
    logs = cursor.fetchall()
    conn.close()
    
    return [{
        'type': log[0],
        'message': log[1],
        'timestamp': log[2]
    } for log in logs]

# Initialize database on startup
init_db()
cleanup_old_data()

# Global variables removed - now using session-based database storage

class HostDiscoveryScanner:
    def __init__(self, session_id, scan_id, scan_name):
        self.nm = nmap.PortScanner()
        self.scanning = False
        self.session_id = session_id
        self.scan_id = scan_id
        self.scan_name = scan_name
        self.scan_dir = get_scan_download_dir(scan_name)
        
    def ping_scan(self, target, ip_list=None):
        """Perform ping scan using nmap"""
        try:
            # Save IP list file if provided
            ip_list_file = None
            if ip_list and ip_list.strip():
                ip_list_file = save_ip_list_file(self.scan_name, ip_list, 'ping')
            
            # Prepare nmap command with scan-specific output
            ping_output = os.path.join(self.scan_dir, 'ping')
            
            if ip_list_file:
                cmd = f"sudo nmap -sn -n -PE -PS -iL {ip_list_file} -oA {ping_output}"
                print(f"Using IP list file: {ip_list_file}")
            elif target and target.strip() and target != 'IP List':
                cmd = f"sudo nmap -sn -n -PE -PS {target} -oA {ping_output}"
            else:
                print(f"Error: No valid target or IP list provided to ping_scan")
                return set()
                
            print(f"Executing ping scan command: {cmd}")
            
            # Use subprocess (let nmap handle its own timing)
            result = subprocess.run(
                cmd, 
                shell=True, 
                capture_output=True, 
                text=True
            )
            
            print(f"Ping scan stdout: {result.stdout}")
            print(f"Ping scan stderr: {result.stderr}")
            
            hosts = set()
            for line in result.stdout.split('\n'):
                if 'Nmap scan report for' in line:
                    ip = line.split()[-1]
                    hosts.add(ip)
            
            print(f"Found {len(hosts)} hosts: {hosts}")
            
            return hosts
        except Exception as e:
            print(f"Ping scan error: {e}")
            return set()
    
    def port_scan(self, target, top_ports=25):
        """Perform port scan using nmap"""
        try:
            cmd = f"sudo nmap -Pn -sS --top-ports {top_ports} {target} -oA port"
            print(f"Executing port scan command: {cmd}")
            
            result = subprocess.run(
                cmd, 
                shell=True, 
                capture_output=True, 
                text=True
            )
            
            print(f"Port scan stdout: {result.stdout}")
            print(f"Port scan stderr: {result.stderr}")
            
            hosts_ports = {}
            current_host = None
            
            print("Parsing port scan output...")
            for line_num, line in enumerate(result.stdout.split('\n')):
                line = line.strip()
                if 'Nmap scan report for' in line:
                    current_host = line.split()[-1]
                    hosts_ports[current_host] = []
                    print(f"Found host: {current_host}")
                elif '/tcp' in line and 'open' in line:
                    if current_host:
                        port = line.split('/')[0]
                        hosts_ports[current_host].append(port)
                        print(f"Found open port {port} on {current_host}")
                elif line and not line.startswith('Nmap') and not line.startswith('Host is up'):
                    print(f"Other line {line_num}: {line}")
            
            print(f"Port scan found {len(hosts_ports)} hosts with open ports: {hosts_ports}")
            return hosts_ports
        except Exception as e:
            print(f"Port scan error: {e}")
            return {}
    
    def port_scan_with_ip_list(self, ip_list, top_ports=25):
        """Perform port scan using nmap with IP list file"""
        try:
            # Save IP list file
            ip_list_file = save_ip_list_file(self.scan_name, ip_list, f'port_{top_ports}')
            
            # Prepare nmap command with scan-specific output
            port_output = os.path.join(self.scan_dir, f'port_{top_ports}')
            
            cmd = f"sudo nmap -Pn -sS --top-ports {top_ports} -iL {ip_list_file} -oA {port_output}"
            print(f"Executing port scan command: {cmd}")
            
            result = subprocess.run(
                cmd, 
                shell=True, 
                capture_output=True, 
                text=True
            )
            
            print(f"Port scan stdout: {result.stdout}")
            print(f"Port scan stderr: {result.stderr}")
            
            hosts_ports = {}
            current_host = None
            
            print("Parsing port scan output...")
            for line_num, line in enumerate(result.stdout.split('\n')):
                line = line.strip()
                if 'Nmap scan report for' in line:
                    current_host = line.split()[-1]
                    hosts_ports[current_host] = []
                    print(f"Found host: {current_host}")
                elif '/tcp' in line and 'open' in line:
                    if current_host:
                        port = line.split('/')[0]
                        hosts_ports[current_host].append(port)
                        print(f"Found open port {port} on {current_host}")
                elif line and not line.startswith('Nmap') and not line.startswith('Host is up'):
                    print(f"Other line {line_num}: {line}")
            
            print(f"Port scan found {len(hosts_ports)} hosts with open ports: {hosts_ports}")
            
            return hosts_ports
        except Exception as e:
            print(f"Port scan error: {e}")
            return {}
    
    def progressive_scan(self, target, ip_list=None):
        """
        Perform progressive host discovery with increasing port ranges.
        
        HOST DISCOVERY LOGIC:
        1. Ping scan to identify responsive hosts
        2. Progressive port scanning (25→50→100→1024) to discover hosts with open ports
        3. Skip hosts already discovered with open ports in subsequent scans
        4. Detect firewall responses (all ports open) and flag separately
        5. Focus on host discovery rather than comprehensive port enumeration
        
        Args:
            target: Target subnet/IP for scanning
            ip_list: List of IPs from textarea input
            
        Returns:
            dict: Scan results with ping_hosts, port_hosts, and firewall_suspected
        """
        print(f"=== STARTING PROGRESSIVE HOST DISCOVERY ===")
        print(f"Session ID: {self.session_id}")
        print(f"Target: {target}")
        print(f"IP List provided: {bool(ip_list and ip_list.strip())}")
        
        self.scanning = True
        
        # Initialize scan results for this session
        scan_results = {
            'scan_status': 'running',
            'start_time': datetime.now(),
            'current_target': target,
            'current_scan_type': '',
            'total_hosts': 0,
            'ping_hosts': set(),
            'port_hosts': {},
            'firewall_suspected': set()
        }
        
        # Save initial state
        save_scan_results(self.scan_id, self.session_id, scan_results)
        
        # Step 1: Ping scan to identify responsive hosts
        scan_results['current_scan_type'] = 'ping'
        
        # Save log entry
        save_scan_log(self.scan_id, self.session_id, 'ping_start', f'Starting ping scan for host discovery')
        
        socketio.emit('scan_update', {
            'type': 'ping_start',
            'message': f'Starting ping scan for host discovery',
            'session_id': self.session_id,
            'scan_id': self.scan_id
        }, room=self.session_id)
        
        ping_hosts = self.ping_scan(target, ip_list)
        scan_results['ping_hosts'] = ping_hosts
        scan_results['total_hosts'] = len(ping_hosts)
        
        # Save ping results
        save_scan_results(self.scan_id, self.session_id, scan_results)
        
        print(f"PING SCAN COMPLETE: Found {len(ping_hosts)} responsive hosts")
        print(f"Responsive hosts: {ping_hosts}")
        
        # Save log entry
        save_scan_log(self.scan_id, self.session_id, 'ping_complete', f'Ping scan complete - Found {len(ping_hosts)} hosts')
        
        socketio.emit('scan_update', {
            'type': 'ping_complete',
            'hosts': list(ping_hosts),
            'count': len(ping_hosts),
            'session_id': self.session_id,
            'scan_id': self.scan_id
        }, room=self.session_id)
        
        # Step 2: Progressive port scanning following user's exact logic
        port_ranges = [25, 50, 100, 1024]
        
        # Create temp file with all IPs for first scan
        temp_file = None
        if ip_list and ip_list.strip():
            temp_file = tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt')
            temp_file.write(ip_list)
            temp_file.close()
            current_ips_file = temp_file.name
        else:
            # Create temp file with ping hosts
            temp_file = tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt')
            temp_file.write('\n'.join(ping_hosts))
            temp_file.close()
            current_ips_file = temp_file.name
        
        print(f"Created initial IPs file: {current_ips_file}")
        
        for port_range in port_ranges:
            if not self.scanning:
                print(f"Scan stopped by user at {port_range} ports")
                break
                
            print(f"\n=== PORT SCAN {port_range} PORTS ===")
            print(f"Scanning IPs from file: {current_ips_file}")
            
            scan_results['current_scan_type'] = f'port_scan_{port_range}'
            # Save log entry
            save_scan_log(self.scan_id, self.session_id, 'port_scan_start', f'Port scanning (top {port_range} ports)')
            
            socketio.emit('scan_update', {
                'type': 'port_scan_start',
                'message': f'Port scanning (top {port_range} ports)',
                'port_range': port_range,
                'remaining_hosts': len(open(current_ips_file).readlines()),
                'session_id': self.session_id,
                'scan_id': self.scan_id
            }, room=self.session_id)
            
            # Perform port scan using temp file
            port_results = self.port_scan_with_ip_list(open(current_ips_file).read(), port_range)
            print(f"Port scan results: {port_results}")
            
            # Process results and detect firewall responses
            new_discoveries = 0
            firewall_detected = 0
            ips_without_ports = []
            
            for host, ports in port_results.items():
                print(f"Processing host {host} with ports {ports}")
                
                if not ports:  # No open ports - add to next scan
                    ips_without_ports.append(host)
                    print(f"Host {host}: No open ports found - will be scanned in next iteration")
                    continue
                    
                # Check for firewall response (all ports open)
                if len(ports) >= port_range * 0.8:  # 80% or more ports open
                    print(f"FIREWALL DETECTED: Host {host} shows {len(ports)}/{port_range} ports open")
                    scan_results['firewall_suspected'].add(host)
                    # Save log entry
                    save_scan_log(self.scan_id, self.session_id, 'firewall_detected', f'Firewall response detected on {host} - {len(ports)}/{port_range} ports open')
                    
                    socketio.emit('scan_update', {
                        'type': 'firewall_detected',
                        'host': host,
                        'ports': ports,
                        'port_range': port_range,
                        'message': f'Firewall response detected - {len(ports)}/{port_range} ports open',
                        'session_id': self.session_id,
                        'scan_id': self.scan_id
                    }, room=self.session_id)
                    firewall_detected += 1
                else:
                    # Genuine host with selective open ports
                    print(f"GENUINE HOST: {host} has {len(ports)} open ports: {ports}")
                    scan_results['port_hosts'][host] = ports
                    new_discoveries += 1
                    
                    # Save log entry
                    save_scan_log(self.scan_id, self.session_id, 'host_discovered', f'Host discovered: {host} with {len(ports)} open ports')
                    
                    socketio.emit('scan_update', {
                        'type': 'host_discovered',
                        'host': host,
                        'ports': ports,
                        'port_range': port_range,
                        'message': f'Host discovered with {len(ports)} open ports',
                        'session_id': self.session_id,
                        'scan_id': self.scan_id
                    }, room=self.session_id)
            
            print(f"PORT SCAN {port_range} COMPLETE:")
            print(f"  - New host discoveries: {new_discoveries}")
            print(f"  - Firewall responses detected: {firewall_detected}")
            print(f"  - IPs without ports (for next scan): {len(ips_without_ports)}")
            
            # Save progress after each port scan
            save_scan_results(self.scan_id, self.session_id, scan_results)
            
            # Save log entry
            save_scan_log(self.scan_id, self.session_id, 'port_scan_complete', f'Port scan {port_range} complete - Discovered: {new_discoveries}, Firewall: {firewall_detected}, Remaining: {len(ips_without_ports)}')
            
            socketio.emit('scan_update', {
                'type': 'port_scan_complete',
                'port_range': port_range,
                'discovered': new_discoveries,
                'firewall_detected': firewall_detected,
                'remaining': len(ips_without_ports),
                'total_discovered': len(scan_results['port_hosts']),
                'session_id': self.session_id,
                'scan_id': self.scan_id
            }, room=self.session_id)
            
            # Create new temp file with IPs that had no open ports for next iteration
            if ips_without_ports:
                os.unlink(current_ips_file)  # Remove old file
                temp_file = tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt')
                temp_file.write('\n'.join(ips_without_ports))
                temp_file.close()
                current_ips_file = temp_file.name
                print(f"Created new IPs file for next scan: {current_ips_file}")
            else:
                print(f"No IPs without ports - stopping progressive scan")
                break
        
        # Clean up final temp file
        if current_ips_file and os.path.exists(current_ips_file):
            os.unlink(current_ips_file)
        
        # Final results summary
        print(f"\n=== HOST DISCOVERY COMPLETE ===")
        print(f"Responsive hosts (ping): {len(scan_results['ping_hosts'])}")
        print(f"Hosts with open ports: {len(scan_results['port_hosts'])}")
        print(f"Firewall suspected: {len(scan_results['firewall_suspected'])}")
        print(f"Discovered hosts: {list(scan_results['port_hosts'].keys())}")
        print(f"Firewall hosts: {list(scan_results['firewall_suspected'])}")
        
        scan_results['scan_status'] = 'completed'
        
        # Save final results
        save_scan_results(self.scan_id, self.session_id, scan_results)
        
        # Update scan status to completed
        update_scan_status(self.scan_id, 'completed')
        
        # Save final log entry
        save_scan_log(self.scan_id, self.session_id, 'scan_complete', 'Host discovery completed successfully')
        
        socketio.emit('scan_update', {
            'type': 'scan_complete',
            'message': 'Host discovery completed successfully',
            'results': {
                'ping_hosts': list(scan_results['ping_hosts']),
                'port_hosts': scan_results['port_hosts'],
                'firewall_suspected': list(scan_results['firewall_suspected'])
            },
            'session_id': self.session_id,
            'scan_id': self.scan_id
        }, room=self.session_id)
        
        self.scanning = False
        return scan_results

# Global scanner instances per scan
active_scanners = {}

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/start_scan', methods=['POST'])
def start_scan():
    session_id = get_or_create_session_id()
    
    data = request.json
    scan_name = data.get('scan_name', '').strip()
    target = data.get('target', '').strip()
    ip_list = data.get('ip_list', '').strip()
    
    print(f"Received scan request - Session: {session_id}, scan_name: '{scan_name}', target: '{target}', ip_list length: {len(ip_list)}")
    
    if not target and not ip_list:
        return jsonify({'error': 'Target or IP list required'}), 400
    
    # Generate default scan name if not provided
    if not scan_name:
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M')
        if target and target != 'IP List':
            scan_name = f'Scan {target} - {timestamp}'
        else:
            ip_count = len(ip_list.split('\n')) if ip_list else 0
            scan_name = f'IP List Scan ({ip_count} IPs) - {timestamp}'
    
    # If we have IP list but no target, use IP list as target
    if ip_list and not target:
        target = 'IP List'
    
    # Create new scan in database
    scan_id = create_scan(session_id, scan_name, target, ip_list)
    
    # Create new scanner for this scan
    scanner = HostDiscoveryScanner(session_id, scan_id, scan_name)
    active_scanners[scan_id] = scanner
    
    # Start scan in background thread
    thread = threading.Thread(target=scanner.progressive_scan, args=(target, ip_list))
    thread.daemon = True
    thread.start()
    
    return jsonify({
        'message': 'Scan started successfully', 
        'session_id': session_id,
        'scan_id': scan_id,
        'scan_name': scan_name
    })

@app.route('/api/stop_scan', methods=['POST'])
def stop_scan():
    session_id = get_or_create_session_id()
    scan_id = request.json.get('scan_id') if request.json else None
    
    if not scan_id:
        return jsonify({'error': 'Scan ID required'}), 400
    
    if scan_id in active_scanners:
        active_scanners[scan_id].scanning = False
        
        # Update scan status in database
        scan_results = get_scan_results(scan_id)
        scan_results['scan_status'] = 'stopped'
        save_scan_results(scan_id, session_id, scan_results)
        update_scan_status(scan_id, 'stopped')
        
        socketio.emit('scan_update', {
            'type': 'scan_stopped',
            'message': 'Scan stopped by user',
            'session_id': session_id,
            'scan_id': scan_id
        }, room=session_id)
        
        # Remove scanner from active scanners
        del active_scanners[scan_id]
        
        return jsonify({'message': 'Scan stopped', 'scan_id': scan_id})
    else:
        return jsonify({'error': 'No active scan found with this scan ID'}), 400

@app.route('/api/scan_status')
def scan_status():
    try:
        session_id = get_or_create_session_id()
        scan_id = request.args.get('scan_id')
        
        if scan_id:
            # Get specific scan results
            scan_results = get_scan_results(scan_id)
            return jsonify({
                'status': scan_results['scan_status'],
                'ping_hosts': list(scan_results['ping_hosts']),
                'port_hosts': scan_results['port_hosts'],
                'firewall_suspected': list(scan_results.get('firewall_suspected', set())),
                'current_target': scan_results['current_target'],
                'current_scan_type': scan_results['current_scan_type'],
                'start_time': scan_results['start_time'].isoformat() if scan_results['start_time'] else None,
                'total_hosts': scan_results['total_hosts'],
                'session_id': session_id,
                'scan_id': scan_id
            })
        else:
            # Get all scans for session
            scans = get_session_scans(session_id)
            return jsonify({
                'session_id': session_id,
                'scans': scans,
                'active_scans': len([s for s in scans if s['status'] in ['running', 'idle']])
            })
    except Exception as e:
        print(f'Error in scan_status: {e}')
        return jsonify({
            'error': 'Failed to get scan status',
            'details': str(e)
        }), 500

@app.route('/api/export_results')
def export_results():
    """Export scan results in various formats"""
    session_id = get_or_create_session_id()
    scan_id = request.args.get('scan_id')
    export_format = request.args.get('format', 'json')
    
    if not scan_id:
        return jsonify({'error': 'Scan ID required'}), 400
    
    scan_results = get_scan_results(scan_id)
    
    results = {
        'scan_info': {
            'target': scan_results['current_target'],
            'start_time': scan_results['start_time'].isoformat() if scan_results['start_time'] else None,
            'status': scan_results['scan_status'],
            'total_hosts': scan_results['total_hosts'],
            'session_id': session_id,
            'scan_id': scan_id
        },
        'ping_hosts': list(scan_results['ping_hosts']),
        'port_hosts': scan_results['port_hosts']
    }
    
    if export_format == 'json':
        return jsonify(results)
    elif export_format == 'csv':
        output = io.StringIO()
        writer = csv.writer(output)
        
        # Write header
        writer.writerow(['IP Address', 'Status', 'Open Ports'])
        
        # Write ping hosts
        for host in scan_results['ping_hosts']:
            ports = scan_results['port_hosts'].get(host, [])
            writer.writerow([host, 'Ping Response', ', '.join(ports) if ports else 'No open ports'])
        
        output.seek(0)
        return output.getvalue(), 200, {'Content-Type': 'text/csv'}
    
    elif export_format == 'txt':
        output = []
        output.append(f"Host Discovery Results - {scan_results['current_target']}")
        output.append(f"Session ID: {session_id}")
        output.append(f"Scan Time: {scan_results['start_time']}")
        output.append(f"Status: {scan_results['scan_status']}")
        output.append(f"Total Hosts: {scan_results['total_hosts']}")
        output.append("\n" + "="*50 + "\n")
        
        output.append("PING RESPONSES:")
        for host in scan_results['ping_hosts']:
            output.append(f"  {host}")
        
        output.append("\nOPEN PORTS:")
        for host, ports in scan_results['port_hosts'].items():
            output.append(f"  {host}: {', '.join(ports)}")
        
        return '\n'.join(output), 200, {'Content-Type': 'text/plain'}

@app.route('/api/session_scans')
def get_session_scans_api():
    """Get all scans for the current session"""
    session_id = get_or_create_session_id()
    scans = get_session_scans(session_id)
    
    return jsonify({
        'session_id': session_id,
        'scans': scans,
        'active_scans': len([s for s in scans if s['status'] in ['running', 'idle']])
    })

@app.route('/api/scan_logs')
def get_scan_logs_api():
    """Get log entries for a specific scan"""
    scan_id = request.args.get('scan_id')
    if not scan_id:
        return jsonify({'error': 'Scan ID required'}), 400
    
    logs = get_scan_logs(scan_id)
    return jsonify({
        'scan_id': scan_id,
        'logs': logs
    })

@app.route('/api/scan_files')
def get_scan_files_api():
    """Get list of files for a specific scan"""
    scan_id = request.args.get('scan_id')
    if not scan_id:
        return jsonify({'error': 'Scan ID required'}), 400
    
    # Get scan name from database
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('SELECT scan_name FROM scans WHERE scan_id = ?', (scan_id,))
    result = cursor.fetchone()
    conn.close()
    
    if not result:
        return jsonify({'error': 'Scan not found'}), 404
    
    scan_name = result[0]
    scan_dir = get_scan_download_dir(scan_name)
    
    files = []
    if os.path.exists(scan_dir):
        for filename in os.listdir(scan_dir):
            filepath = os.path.join(scan_dir, filename)
            if os.path.isfile(filepath):
                stat = os.stat(filepath)
                files.append({
                    'name': filename,
                    'size': stat.st_size,
                    'modified': datetime.fromtimestamp(stat.st_mtime).isoformat(),
                    'download_url': f'/api/download_file?scan_id={scan_id}&file={filename}'
                })
    
    return jsonify({
        'scan_id': scan_id,
        'scan_name': scan_name,
        'files': files
    })

@app.route('/api/download_file')
def download_file_api():
    """Download a specific file from a scan"""
    scan_id = request.args.get('scan_id')
    filename = request.args.get('file')
    
    if not scan_id or not filename:
        return jsonify({'error': 'Scan ID and filename required'}), 400
    
    # Get scan name from database
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('SELECT scan_name FROM scans WHERE scan_id = ?', (scan_id,))
    result = cursor.fetchone()
    conn.close()
    
    if not result:
        return jsonify({'error': 'Scan not found'}), 404
    
    scan_name = result[0]
    scan_dir = get_scan_download_dir(scan_name)
    filepath = os.path.join(scan_dir, filename)
    
    if not os.path.exists(filepath):
        return jsonify({'error': 'File not found'}), 404
    
    return send_file(filepath, as_attachment=True, download_name=filename)

@socketio.on('connect')
def handle_connect():
    session_id = get_or_create_session_id()
    print(f'Client connected with session: {session_id}')
    
    # Join the session-specific room
    join_room(session_id)
    
    emit('scan_update', {
        'type': 'connected',
        'message': 'Connected to scan server',
        'session_id': session_id
    }, room=session_id)

@socketio.on('disconnect')
def handle_disconnect():
    session_id = get_or_create_session_id()
    print(f'Client disconnected from session: {session_id}')
    
    # Leave the session-specific room
    leave_room(session_id)

if __name__ == '__main__':
    socketio.run(app, debug=True, host='0.0.0.0', port=5000, allow_unsafe_werkzeug=True)
