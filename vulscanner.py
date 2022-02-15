import portscanner

targets_ip = input('[+] * Enter the targets to scan for vulnerable ports: ')
port_number = int(input('[+] * Enter the number of ports to scan for vulnerabilities: '))
vul_file = input('[+] * Enter the path to the file to scan for vulnerable software: ')
print('\n')

target = portscanner.PortScan(targets_ip, port_number)
target.scan()
with open(vul_file, 'r') as file:
    count = 0
    for banner in target.banners:
        file.seek(0)
        for line in file.readlines():
            if line.strip() in banner:
                print('[!!] VULNERABLE BANNER FOUND: "' + banner + '" +ON PORT: ' + str(target.open_ports[count]))
        count += 1
