import nmap
import traceback

nmap_path = '/opt/homebrew/bin/nmap'

if nmap_path:
    nmap.PortScanner.nmap_path = nmap_path

def identify_services(target, ports):
    """Identify services running on open ports.
    
    IMPORTANT: Target and ports are pre-validated by the route handler using app.validators
    module. This function assumes inputs are safe to pass to nmap.
    
    Args:
        target (str): Pre-validated target IP, CIDR, domain, or IPv6 address
        ports (list): Pre-validated list of integers representing open ports (1-65535)
        
    Returns:
        dict: Dictionary mapping port numbers to service information (name, product, version)
    """
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
        
        protocols = [proto for proto in ('tcp', 'udp') if proto in host_data]
        if not protocols:
            return {'service': 'Error', 'banner': 'No TCP/UDP data found'}
        
        for protocol in protocols:
            port_block = host_data.get(protocol, {})
            print(f"📋 {protocol.upper()} ports found: {list(port_block.keys())}")
            
            for port in ports:
                try:
                    port_key = int(port)
                    
                    if port_key not in port_block:
                        print(f"  ⚠️ Port {port}/{protocol}: Not in {protocol.upper()} data")
                        continue
                    
                    port_data = port_block[port_key]
                    print(f"  📦 Port {port}/{protocol} data: {port_data}")
                    
                    service_name = (
                        port_data.get('name') or
                        port_data.get('product') or
                        port_data.get('service') or
                        'unknown'
                    )
                    
                    product = port_data.get('product') or 'unknown'
                    
                    version_info = port_data.get('version') or ''
                    extra_info = port_data.get('extrainfo') or ''
                    if isinstance(version_info, list):
                        version_info = ' '.join(map(str, version_info))
                    if isinstance(extra_info, list):
                        extra_info = ' '.join(map(str, extra_info))
                    
                    services[port] = {
                        'service': str(service_name),
                        'product': str(product) if product else 'unknown',
                        'version': str(version_info) if version_info else 'N/A',
                        'extra_info': str(extra_info) if extra_info else None,
                        'protocol': protocol,
                        'reason': port_data.get('reason'),
                        'tunnel': port_data.get('tunnel'),
                        'conf': port_data.get('conf'),
                    }
                    
                    print(f"  ✅ Port {port}/{protocol}: {service_name} {product} {version_info}")
                    
                except Exception as e:
                    print(f"  ⚠️ Port {port}/{protocol}: Error - {e}")
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
