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
from datetime import datetime
from flask import Flask, render_template, request, jsonify
from flask_socketio import SocketIO, emit
import nmap

app = Flask(__name__)
app.config['SECRET_KEY'] = 'host_discovery_secret_key'
socketio = SocketIO(app, cors_allowed_origins="*")

# Global variables to store scan results
scan_results = {
    'ping_hosts': set(),
    'port_hosts': {},
    'scan_status': 'idle',
    'current_target': '',
    'current_scan_type': '',
    'start_time': None,
    'total_hosts': 0
}

class HostDiscoveryScanner:
    def __init__(self):
        self.nm = nmap.PortScanner()
        self.scanning = False
        
    def ping_scan(self, target, ip_list=None):
        """Perform ping scan using nmap"""
        try:
            # If we have IP list, use it regardless of target
            if ip_list and ip_list.strip():
                import tempfile
                temp_file = tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt')
                temp_file.write(ip_list)
                temp_file.close()
                cmd = f"sudo nmap -sn -n -PE -PS -iL {temp_file.name} -oA ping"
                print(f"Using IP list file: {temp_file.name}")
            elif target and target.strip() and target != 'IP List':
                cmd = f"sudo nmap -sn -n -PE -PS {target} -oA ping"
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
            
            # Clean up temporary file
            if 'temp_file' in locals() and temp_file:
                import os
                os.unlink(temp_file.name)
                
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
            import tempfile
            temp_file = tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt')
            temp_file.write(ip_list)
            temp_file.close()
            
            cmd = f"sudo nmap -Pn -sS --top-ports {top_ports} -iL {temp_file.name} -oA port"
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
            
            # Clean up temporary file
            import os
            os.unlink(temp_file.name)
            
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
        global scan_results
        
        print(f"=== STARTING PROGRESSIVE HOST DISCOVERY ===")
        print(f"Target: {target}")
        print(f"IP List provided: {bool(ip_list and ip_list.strip())}")
        
        self.scanning = True
        scan_results['scan_status'] = 'running'
        scan_results['start_time'] = datetime.now()
        scan_results['current_target'] = target
        
        # Initialize firewall detection
        scan_results['firewall_suspected'] = set()
        
        # Step 1: Ping scan to identify responsive hosts
        scan_results['current_scan_type'] = 'ping'
        socketio.emit('scan_update', {
            'type': 'ping_start',
            'message': f'Starting ping scan for host discovery'
        })
        
        ping_hosts = self.ping_scan(target, ip_list)
        scan_results['ping_hosts'] = ping_hosts
        scan_results['total_hosts'] = len(ping_hosts)
        
        print(f"PING SCAN COMPLETE: Found {len(ping_hosts)} responsive hosts")
        print(f"Responsive hosts: {ping_hosts}")
        
        socketio.emit('scan_update', {
            'type': 'ping_complete',
            'hosts': list(ping_hosts),
            'count': len(ping_hosts)
        })
        
        # Step 2: Progressive port scanning following user's exact logic
        port_ranges = [25, 50, 100, 1024]
        
        # Create temp file with all IPs for first scan
        import tempfile
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
            socketio.emit('scan_update', {
                'type': 'port_scan_start',
                'message': f'Port scanning (top {port_range} ports)',
                'port_range': port_range,
                'remaining_hosts': len(open(current_ips_file).readlines())
            })
            
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
                    socketio.emit('scan_update', {
                        'type': 'firewall_detected',
                        'host': host,
                        'ports': ports,
                        'port_range': port_range,
                        'message': f'Firewall response detected - {len(ports)}/{port_range} ports open'
                    })
                    firewall_detected += 1
                else:
                    # Genuine host with selective open ports
                    print(f"GENUINE HOST: {host} has {len(ports)} open ports: {ports}")
                    scan_results['port_hosts'][host] = ports
                    new_discoveries += 1
                    
                    socketio.emit('scan_update', {
                        'type': 'host_discovered',
                        'host': host,
                        'ports': ports,
                        'port_range': port_range,
                        'message': f'Host discovered with {len(ports)} open ports'
                    })
            
            print(f"PORT SCAN {port_range} COMPLETE:")
            print(f"  - New host discoveries: {new_discoveries}")
            print(f"  - Firewall responses detected: {firewall_detected}")
            print(f"  - IPs without ports (for next scan): {len(ips_without_ports)}")
            
            socketio.emit('scan_update', {
                'type': 'port_scan_complete',
                'port_range': port_range,
                'discovered': new_discoveries,
                'firewall_detected': firewall_detected,
                'remaining': len(ips_without_ports),
                'total_discovered': len(scan_results['port_hosts'])
            })
            
            # Create new temp file with IPs that had no open ports for next iteration
            if ips_without_ports:
                import os
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
            import os
            os.unlink(current_ips_file)
        
        # Final results summary
        print(f"\n=== HOST DISCOVERY COMPLETE ===")
        print(f"Responsive hosts (ping): {len(scan_results['ping_hosts'])}")
        print(f"Hosts with open ports: {len(scan_results['port_hosts'])}")
        print(f"Firewall suspected: {len(scan_results['firewall_suspected'])}")
        print(f"Discovered hosts: {list(scan_results['port_hosts'].keys())}")
        print(f"Firewall hosts: {list(scan_results['firewall_suspected'])}")
        
        scan_results['scan_status'] = 'completed'
        socketio.emit('scan_update', {
            'type': 'scan_complete',
            'message': 'Host discovery completed successfully',
            'results': {
                'ping_hosts': list(scan_results['ping_hosts']),
                'port_hosts': scan_results['port_hosts'],
                'firewall_suspected': list(scan_results['firewall_suspected'])
            }
        })
        
        self.scanning = False
        return scan_results

scanner = HostDiscoveryScanner()

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/start_scan', methods=['POST'])
def start_scan():
    global scan_results
    
    if scanner.scanning:
        return jsonify({'error': 'Scan already in progress'}), 400
    
    data = request.json
    target = data.get('target', '').strip()
    ip_list = data.get('ip_list', '').strip()
    
    print(f"Received scan request - target: '{target}', ip_list length: {len(ip_list)}")
    
    if not target and not ip_list:
        return jsonify({'error': 'Target or IP list required'}), 400
    
    # If we have IP list but no target, use IP list as target
    if ip_list and not target:
        target = 'IP List'
    
    # Reset results
    scan_results = {
        'ping_hosts': set(),
        'port_hosts': {},
        'scan_status': 'running',
        'current_target': target or 'IP List',
        'current_scan_type': '',
        'start_time': None,
        'total_hosts': 0
    }
    
    # Start scan in background thread
    thread = threading.Thread(target=scanner.progressive_scan, args=(target, ip_list))
    thread.daemon = True
    thread.start()
    
    return jsonify({'message': 'Scan started successfully'})

@app.route('/api/stop_scan', methods=['POST'])
def stop_scan():
    scanner.scanning = False
    scan_results['scan_status'] = 'stopped'
    socketio.emit('scan_update', {
        'type': 'scan_stopped',
        'message': 'Scan stopped by user'
    })
    return jsonify({'message': 'Scan stopped'})

@app.route('/api/scan_status')
def scan_status():
    return jsonify({
        'status': scan_results['scan_status'],
        'ping_hosts': list(scan_results['ping_hosts']),
        'port_hosts': scan_results['port_hosts'],
        'firewall_suspected': list(scan_results.get('firewall_suspected', set())),
        'current_target': scan_results['current_target'],
        'current_scan_type': scan_results['current_scan_type'],
        'start_time': scan_results['start_time'].isoformat() if scan_results['start_time'] else None,
        'total_hosts': scan_results['total_hosts']
    })

@app.route('/api/export_results')
def export_results():
    """Export scan results in various formats"""
    export_format = request.args.get('format', 'json')
    
    results = {
        'scan_info': {
            'target': scan_results['current_target'],
            'start_time': scan_results['start_time'].isoformat() if scan_results['start_time'] else None,
            'status': scan_results['scan_status'],
            'total_hosts': scan_results['total_hosts']
        },
        'ping_hosts': list(scan_results['ping_hosts']),
        'port_hosts': scan_results['port_hosts']
    }
    
    if export_format == 'json':
        return jsonify(results)
    elif export_format == 'csv':
        import csv
        import io
        
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

@socketio.on('connect')
def handle_connect():
    print('Client connected')
    emit('scan_update', {
        'type': 'connected',
        'message': 'Connected to scan server'
    })

@socketio.on('disconnect')
def handle_disconnect():
    print('Client disconnected')

if __name__ == '__main__':
    socketio.run(app, debug=True, host='0.0.0.0', port=5000, allow_unsafe_werkzeug=True)
