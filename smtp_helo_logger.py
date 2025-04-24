#!/usr/bin/env python3
"""
SMTP HELO/EHLO Logger - Captures and logs outgoing SMTP HELO/EHLO commands and responses

To run in foreground mode (for testing):
sudo ./smtp_helo_logger.py --foreground

To run in background, for logging:
sudo ./smtp_helo_logger.py
"""

import subprocess
import re
import time
import os
import signal
import sys
import socket
from datetime import datetime

# Configuration
LOG_FILE = "/var/log/smtp_helo.log"
INTERFACE = "eth0"  # Change this to your network interface
PORT = 25  # SMTP port

def get_local_ip():
    """Get the local IP address of the server for the specified interface"""
    try:
        # Get IP address of the specified interface
        cmd = f"ip addr show {INTERFACE} | grep 'inet ' | awk '{{print $2}}' | cut -d/ -f1"
        result = subprocess.check_output(cmd, shell=True, text=True).strip()
        if result:
            return result
        else:
            # Fallback method if specific interface doesn't work
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
    except Exception as e:
        print(f"Error getting local IP: {e}")
        print("Will capture all SMTP traffic instead of just outgoing")
        return None

def setup_logging():
    """Ensure log file is writable and create it if it doesn't exist"""
    try:
        log_dir = os.path.dirname(LOG_FILE)
        if log_dir and not os.path.exists(log_dir):
            os.makedirs(log_dir)
        # Test write to the log file
        with open(LOG_FILE, 'a') as f:
            timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            f.write(f"[{timestamp}] SMTP HELO/EHLO Logger started\n")
        return True
    except Exception as e:
        print(f"Error setting up logging: {e}")
        return False

def log_message(message):
    """Write a message to the log file"""
    try:
        with open(LOG_FILE, 'a') as f:
            timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            f.write(f"[{timestamp}] {message}\n")
    except Exception as e:
        print(f"Error writing to log: {e}")

def process_packet(packet_data):
    """Process captured packet data and extract HELO/EHLO information"""
    # Match HELO or EHLO commands
    helo_match = re.search(r'(?i)(HELO|EHLO)\s+(\S+)', packet_data)
    if helo_match:
        command = helo_match.group(1).upper()
        domain = helo_match.group(2)
        log_message(f"Client {command}: {domain}")
    
    # Match server response to HELO/EHLO
    response_match = re.search(r'250(?:-|\s)(\S+)\s+Hello\s+(.+)', packet_data)
    if response_match:
        server_name = response_match.group(1)
        client_info = response_match.group(2)
        log_message(f"Server response: 250 {server_name} Hello {client_info}")

def capture_smtp_traffic():
    """Capture outgoing SMTP traffic and process packets"""
    try:
        # Get local IP address
        local_ip = get_local_ip()
        
        # Use tcpdump to capture SMTP traffic
        tcpdump_cmd = [
            "tcpdump", 
            "-i", INTERFACE,
            "-l",  # Line-buffered output
            "-A",  # Print packet contents in ASCII
            "-s", "0",  # Capture entire packets
        ]
        
        # Add filter for outgoing SMTP traffic if we could get the local IP
        if local_ip:
            filter_expr = f"port {PORT} and src host {local_ip}"
            log_message(f"Filtering for outgoing SMTP traffic from {local_ip}")
        else:
            filter_expr = f"port {PORT}"
            log_message("Capturing all SMTP traffic (could not determine local IP)")
        
        tcpdump_cmd.append(filter_expr)
        
        # Start tcpdump process
        tcpdump_process = subprocess.Popen(
            tcpdump_cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1  # Line buffered
        )
        
        log_message(f"Started capturing SMTP traffic on {INTERFACE} port {PORT}")
        print(f"Logging outgoing SMTP HELO/EHLO to {LOG_FILE}")
        
        # Process output
        packet_data = ""
        while True:
            line = tcpdump_process.stdout.readline()
            if not line:
                break
                
            # Add line to current packet data
            packet_data += line
            
            # If we reach end of packet, process it and reset
            if line.strip() == "":
                process_packet(packet_data)
                packet_data = ""
                
    except KeyboardInterrupt:
        log_message("Logger stopped by user")
        print("\nLogger stopped")
    except Exception as e:
        log_message(f"Error: {e}")
        print(f"Error: {e}")
    finally:
        # Clean up
        if 'tcpdump_process' in locals():
            tcpdump_process.terminate()
            tcpdump_process.wait()

def handle_signal(sig, frame):
    """Handle interrupt signals"""
    log_message("Logger stopped by signal")
    print("\nLogger stopped")
    sys.exit(0)

def run_as_daemon():
    """Run the script as a daemon process"""
    try:
        # Fork the process
        pid = os.fork()
        if pid > 0:
            # Exit the parent process
            print(f"SMTP HELO/EHLO Logger started with PID: {pid}")
            print(f"Logging to: {LOG_FILE}")
            sys.exit(0)
    except OSError as e:
        print(f"Fork failed: {e}")
        sys.exit(1)
    
    # Decouple from parent environment
    os.chdir('/')
    os.setsid()
    os.umask(0)
    
    # Close standard file descriptors
    sys.stdout.flush()
    sys.stderr.flush()
    si = open(os.devnull, 'r')
    so = open(os.devnull, 'a+')
    se = open(os.devnull, 'a+')
    os.dup2(si.fileno(), sys.stdin.fileno())
    os.dup2(so.fileno(), sys.stdout.fileno())
    os.dup2(se.fileno(), sys.stderr.fileno())
    
    # Run the main function
    capture_smtp_traffic()

if __name__ == "__main__":
    # Register signal handlers
    signal.signal(signal.SIGINT, handle_signal)
    signal.signal(signal.SIGTERM, handle_signal)
    
    # Ensure logging is set up correctly
    if not setup_logging():
        sys.exit(1)
    
    # Check if script has root privileges (needed for tcpdump)
    if os.geteuid() != 0:
        print("This script needs to be run with root privileges (sudo)")
        sys.exit(1)
    
    # Check if --foreground flag is provided
    if len(sys.argv) > 1 and sys.argv[1] == "--foreground":
        print(f"Running in foreground mode. Logging to {LOG_FILE}")
        capture_smtp_traffic()
    else:
        run_as_daemon()

