import socket
import os
import nmap
import traceback

nmap_path = '/opt/homebrew/bin/nmap'

if os.path.exists(nmap_path):
    nmap.PortScanner.nmap_path = nmap_path
    print(f"✅ Using nmap from: {nmap_path}")
else:
    print(f"⚠️ nmap not found at {nmap_path}")

def scan_ports(target, ports=None, timeout=1):
    """Scan ports using nmap library with error handling.
    
    IMPORTANT: Target and ports are pre-validated by the route handler using app.validators
    module. This function assumes inputs are safe to pass to nmap.
    
    Args:
        target (str): Pre-validated target IP, CIDR, domain, or IPv6 address
        ports (list, optional): Pre-validated list of integers (1-65535). 
                               Defaults to common ports if not specified.
        timeout (int): nmap timeout in seconds
        
    Returns:
        list: List of open ports found on target
    """
    if ports is None:
        ports = [22, 80, 443, 4443, 8000, 8080, 8081, 3306, 5432, 8443]
    
    open_ports = []
    
    try:
        nm = nmap.PortScanner()
        print(f"🔍 Starting nmap scan on {target}...")
        
        nm.scan(target, arguments=f'-p {",".join(map(str, ports))} -T4 --open -host-timeout 60s')
        
        print(f"🔍 Scan completed. Checking results...")
        
        # ✅ FIX: nmap returns results by IP, not hostname
        host_key = None
        for host in nm.all_hosts():
            if host == target or nm[host].hostname() == target:
                host_key = host
                break
        
        if host_key is None:
            print(f"❌ Could not find host key for {target}")
            print(f"📋 Available hosts: {nm.all_hosts()}")
            return open_ports
        
        print(f"✅ Using host key: {host_key}")
        
        for port in ports:
            try:
                if nm[host_key].has_tcp(port):
                    state = nm[host_key]['tcp'][port]['state']
                    if state == 'open':
                        open_ports.append(port)
                        print(f"  ✅ Port {port} is OPEN")
            except KeyError:
                continue
        
        print(f"📊 Total open ports: {open_ports}")
                
    except nmap.PortScannerError as e:
        print(f"❌ Nmap error: {e}")
    except socket.gaierror as e:
        print(f"❌ DNS resolution failed: {e}")
    except Exception as e:
        print(f"❌ Scan error: {e}")
        print(traceback.format_exc())
    
    return open_ports
