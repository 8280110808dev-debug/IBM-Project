import nmap

def scan_target(target):

    scanner = nmap.PortScanner()

    scanner.scan(target, '1-1024')

    results = []

    for host in scanner.all_hosts():

        for proto in scanner[host].all_protocols():

            ports = scanner[host][proto].keys()

            for port in ports:

                state = scanner[host][proto][port]['state']

                if port in [21, 23]:
                    risk = "HIGH RISK"

                elif port in [80, 443]:
                    risk = "MEDIUM RISK"

                else:
                    risk = "LOW RISK"

                results.append(
                    f"Port {port} : {state} : {risk}"
                )

    return results
