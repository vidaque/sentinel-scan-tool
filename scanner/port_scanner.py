import nmap

def run(target, is_scanning_callback):
    nm = nmap.PortScanner()
    results = []

    try:
        results.append(f"[i] Scanning target: {target}")
        nm.scan(hosts=target, arguments='-T4 -F')

        for host in nm.all_hosts():
            if not is_scanning_callback():
                results.append("[!] Scan stopped early.")
                break

            results.append(f"\nHost: {host} ({nm[host].hostname()})")
            results.append(f"State: {nm[host].state()}")

            for proto in nm[host].all_protocols():
                lport = nm[host][proto].keys()
                for port in sorted(lport):
                    state = nm[host][proto][port]['state']
                    name = nm[host][proto][port].get('name', 'unknown')
                    product = nm[host][proto][port].get('product', '')
                    version = nm[host][proto][port].get('version', '')
                    info = f"{proto.upper()} {port}/ {state}  {name} {product} {version}".strip()
                    results.append(info)

        if not results:
            results.append("[!] No hosts found or scan incomplete.")

    except Exception as e:
        results.append(f"[ERROR] {str(e)}")

    return "\n".join(results)
