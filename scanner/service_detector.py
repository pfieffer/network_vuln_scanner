import nmap
import traceback

nmap_path = '/opt/homebrew/bin/nmap'

if nmap_path:
    nmap.PortScanner.nmap_path = nmap_path

def identify_services(target, ports):
    """Identify services running on open ports."""
    services = {}
    
    try:
        nm = nmap.PortScanner()
        print(f"🔍 Running service detection on {target}...")
        
        nm.scan(target, arguments=f'-p {",".join(map(str, ports))} -sV --version-intensity 5')
        
        hosts = nm.all_hosts()
        if not hosts:
            return {'service': 'Error', 'banner': 'No hosts found'}
        
        host_key = str(hosts[0])
        print(f"✅ Using host key: {host_key}")
        
        host_data = nm[host_key]
        
        # ✅ Port data is under ['tcp'] key!
        if 'tcp' not in host_data:
            return {'service': 'Error', 'banner': 'No TCP data found'}
        
        tcp_data = host_data['tcp']
        print(f"📋 TCP ports found: {list(tcp_data.keys())}")
        
        for port in ports:
            try:
                port_key = int(port)
                
                if port_key not in tcp_data:
                    print(f"  ⚠️ Port {port}: Not in TCP data")
                    continue
                
                port_data = tcp_data[port_key]
                print(f"  📦 Port {port} data: {port_data}")
                
                # Extract service name
                service_name = (
                    port_data.get('name', 'unknown') or
                    port_data.get('product', 'unknown') or
                    'unknown'
                )
                
                # Extract version
                version_info = (
                    port_data.get('version', '') or
                    port_data.get('extrainfo', '') or
                    ''
                )
                
                if isinstance(version_info, list):
                    version_info = ' '.join(map(str, version_info))
                
                services[port] = {
                    'service': str(service_name),
                    'version': str(version_info) if version_info else 'N/A'
                }
                
                print(f"  ✅ Port {port}: {service_name} v{version_info}")
                
            except Exception as e:
                print(f"  ⚠️ Port {port}: Error - {e}")
                continue
        
        print(f"📊 Services found: {services}")
        return services
        
    except nmap.PortScannerError as e:
        print(f"❌ Nmap error: {e}")
        return {'service': 'Error', 'banner': str(e)}
    except Exception as e:
        print(f"❌ Service detection error: {e}")
        traceback.print_exc()
        return {'service': 'Error', 'banner': str(e)}
