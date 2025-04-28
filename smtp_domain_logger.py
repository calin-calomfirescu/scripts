#!/usr/bin/env python3
"""
SMTP Domain Logger - Captures and logs outgoing SMTP dialogues to domain-specific log files
Excludes message data while recording the SMTP command sequence
"""

import subprocess
import re
import os
import signal
import sys
import socket
import time
from datetime import datetime

# Configuration
LOG_DIR = "/var/log/smtp-domains"  # Base directory for domain-specific logs
INTERFACE = "eth0"  # Change this to your network interface
PORT = 25  # SMTP port
MAX_LOG_SIZE = 10 * 1024 * 1024  # 10MB max log file size before rotation

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
    """Ensure log directory exists"""
    try:
        if not os.path.exists(LOG_DIR):
            os.makedirs(LOG_DIR)
        
        # Create a general log file for startup messages
        with open(f"{LOG_DIR}/smtp_logger.log", 'a') as f:
            timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            f.write(f"[{timestamp}] SMTP Domain Logger started\n")
        return True
    except Exception as e:
        print(f"Error setting up logging: {e}")
        return False

def log_message(domain, message):
    """Write a message to the domain-specific log file"""
    try:
        # Sanitize domain name for use as filename
        log_file = os.path.join(LOG_DIR, domain.replace('/', '_'))
        
        # Check if log rotation is needed
        if os.path.exists(log_file) and os.path.getsize(log_file) > MAX_LOG_SIZE:
            # Rotate log file
            timestamp = datetime.now().strftime('%Y%m%d-%H%M%S')
            os.rename(log_file, f"{log_file}.{timestamp}")
        
        with open(log_file, 'a') as f:
            timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            f.write(f"[{timestamp}] {message}\n")
    except Exception as e:
        # Log to general log file if domain-specific logging fails
        with open(f"{LOG_DIR}/smtp_logger.log", 'a') as f:
            f.write(f"Error writing to {domain} log: {e}\n")

class SMTPSession:
    """Track and log an SMTP session"""
    def __init__(self, src_ip, dst_ip, dst_port):
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.dst_port = dst_port
        self.domain = "unknown"  # Will be updated once resolved
        self.commands = []
        self.in_data_mode = False
        self.session_id = f"{src_ip}:{dst_ip}:{int(time.time())}"
        self.active = True
        self.start_time = datetime.now()
        
        # Try to resolve the destination IP to domain name
        try:
            hostname, _, _ = socket.gethostbyaddr(dst_ip)
            self.domain = hostname
        except:
            # If reverse DNS fails, use the IP as the domain
            self.domain = dst_ip
        
        # Sanitize domain to make it appropriate for a filename
        self.log_domain = re.sub(r'[^a-zA-Z0-9.-]', '_', self.domain)
        
        # Log session start
        log_message(self.log_domain, f"Session started: {self.src_ip} -> {self.domain} ({self.dst_ip})")

    def add_command(self, command, response=None):
        """Add a command and optional response to the session log"""
        if command.upper().startswith("DATA"):
            self.in_data_mode = True
            log_message(self.log_domain, f"Command: {command}")
            if response:
                log_message(self.log_domain, f"Response: {response}")
        elif self.in_data_mode and command.strip() == ".":
            self.in_data_mode = False
            log_message(self.log_domain, "Command: <END OF DATA>")
            if response:
                log_message(self.log_domain, f"Response: {response}")
        elif not self.in_data_mode:
            # Don't log the message content, only log SMTP commands
            log_message(self.log_domain, f"Command: {command}")
            if response:
                log_message(self.log_domain, f"Response: {response}")

    def close(self, reason="Connection closed"):
        """Close the session and log the final status"""
        if self.active:
            duration = (datetime.now() - self.start_time).total_seconds()
            log_message(self.log_domain, f"Session ended: {reason} (Duration: {duration:.2f}s)")
            self.active = False

def process_packet(packet, sessions):
    """Process a packet and update the relevant SMTP session"""
    # Extract packet details
    match = re.search(r'IP\s+([0-9.]+)\.([0-9]+)\s+>\s+([0-9.]+)\.([0-9]+)', packet)
    if not match:
        return sessions
    
    src_ip = match.group(1)
    src_port = match.group(2)
    dst_ip = match.group(3)
    dst_port = match.group(4)
    
    # Create a session key
    session_key = f"{src_ip}:{src_port}-{dst_ip}:{dst_port}"
    reverse_key = f"{dst_ip}:{dst_port}-{src_ip}:{src_port}"
    
    # Extract SMTP command or response
    if "Flags [P.]" in packet and ":" in packet:
        payload_lines = packet.split("\n")
        for i, line in enumerate(payload_lines):
            if ": " in line:
                # The actual SMTP data starts after the line with ": "
                smtp_data = "\n".join(payload_lines[i+1:])
                smtp_lines = smtp_data.strip().split("\n")
                
                # Process the SMTP data
                if session_key in sessions:
                    session = sessions[session_key]
                    is_client = True
                elif reverse_key in sessions:
                    session = sessions[reverse_key]
                    is_client = False
                else:
                    # New outgoing session
                    if is_local_ip(src_ip):
                        session = SMTPSession(src_ip, dst_ip, dst_port)
                        sessions[session_key] = session
                        is_client = True
                    else:
                        # We don't track incoming sessions
                        return sessions
                
                # Process each line of the SMTP data
                for line in smtp_lines:
                    line = line.strip()
                    if not line:
                        continue
                    
                    if is_client:
                        # Client command
                        session.add_command(line)
                    else:
                        # Server response - find the last command without a response
                        if session.commands and session.commands[-1][1] is None:
                            session.commands[-1] = (session.commands[-1][0], line)
                        # Log the response
                        log_message(session.log_domain, f"Response: {line}")
                
                break
    
    # Check for connection termination
    if "Flags [F.]" in packet:
        if session_key in sessions:
            sessions[session_key].close()
            del sessions[session_key]
        elif reverse_key in sessions:
            sessions[reverse_key].close()
            del sessions[reverse_key]
    
    return sessions

def is_local_ip(ip):
    """Check if an IP is a local IP address for this server"""
    local_ip = get_local_ip()
    return ip == local_ip

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
            "-n",  # Don't convert addresses
            "-s", "0",  # Capture entire packets
        ]
        
        # Add filter for outgoing SMTP traffic if we could get the local IP
        if local_ip:
            filter_expr = f"tcp port {PORT} and src host {local_ip}"
            log_message("general", f"Filtering for outgoing SMTP traffic from {local_ip}")
        else:
            filter_expr = f"tcp port {PORT}"
            log_message("general", "Capturing all SMTP traffic (could not determine local IP)")
        
        tcpdump_cmd.append(filter_expr)
        
        # Start tcpdump process
        tcpdump_process = subprocess.Popen(
            tcpdump_cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1  # Line buffered
        )
        
        log_message("general", f"Started capturing SMTP traffic on {INTERFACE} port {PORT}")
        print(f"Logging outgoing SMTP traffic to domain-specific files in {LOG_DIR}")
        
        # Track active sessions
        active_sessions = {}
        
        # Process tcpdump output
        packet = ""
        while True:
            line = tcpdump_process.stdout.readline()
            if not line:
                break
            
            # Check if this is the start of a new packet
            if line.startswith("\t") or line.startswith("    "):
                # Continuation of the current packet
                packet += line
            else:
                # Process the previous packet if we have one
                if packet:
                    active_sessions = process_packet(packet, active_sessions)
                
                # Start a new packet
                packet = line
        
        # Process the last packet
        if packet:
            process_packet(packet, active_sessions)
            
    except KeyboardInterrupt:
        log_message("general", "Logger stopped by user")
        print("\nLogger stopped")
    except Exception as e:
        log_message("general", f"Error: {e}")
        print(f"Error: {e}")
    finally:
        # Clean up
        if 'tcpdump_process' in locals():
            tcpdump_process.terminate()
            tcpdump_process.wait()

def handle_signal(sig, frame):
    """Handle interrupt signals"""
    log_message("general", "Logger stopped by signal")
    print("\nLogger stopped")
    sys.exit(0)

def run_as_daemon():
    """Run the script as a daemon process"""
    try:
        # Fork the process
        pid = os.fork()
        if pid > 0:
            # Exit the parent process
            print(f"SMTP Domain Logger started with PID: {pid}")
            print(f"Logging to: {LOG_DIR}")
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
        print(f"Running in foreground mode. Logging to {LOG_DIR}")
        capture_smtp_traffic()
    else:
        run_as_daemon()
        