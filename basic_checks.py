#!/bin/python3
# This program is supposed to automatize basic test for web interface
# @authors ybeattie
# @version 2.0

import argparse
import ipaddress
from nslookup import Nslookup
import subprocess
import shlex
import nmap
import threading
import xml.etree.ElementTree as ET
import os 

def parse():
    '''This function defines the argument of our script'''
    parser = argparse.ArgumentParser(
        prog="Basic checks for web pentests",
        description="Those checks include nmap, sslcompare, headerexposer,feroxbuster,...",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    parser.add_argument("-f", "--scope", help="Scope file (IP range, IP addresse, domains)", required=True)
    parser.add_argument("--force", action="store_true", help="Force script to execute (even without Lab-IP)", required=False)
    parser.add_argument("--ferox-args", help="Argument provided to the fuzzing part. See 'feroxbuster -h' for felp", required=False, default="--smart --burp -C 404 --thorough -r -w /usr/share/wordlists/seclists/Discovery/Web-Content/raft-medium-files.txt")
    #parser.add_argument("-o", "--output", help="Output file", required=False)
    return parser.parse_args()

def run_cmd(cmd, stdout=None, stderr=None):
    '''This is a special function for running bash cmd and printing or not de result'''
    print(f'Running {cmd}')
    return subprocess.run(cmd.split(' '), encoding='utf-8', stdout=stdout, stderr=stderr)

def check_http_methods(domains):
    ''' Checks http methods with nmap (not great)'''
    for domain in domains:
        print(f'Checking the autorized methods on {domain}')
        run_cmd(f'nmap --script http-methods {domain}')

def check_http_redirect(ip, port):
    ''' Checks if the http port redirects to https'''
    print(f"Checking if http request on {ip} redirects to https")
    run_cmd(f'curl http://{ip}:{port}')

def def_ips_domain(file):
    '''This function defines our scope based on the input file'''
    ips = []
    domains = []
    for line in file.readlines():
        line = line.strip()
        try:
            if ('-' in line or '/' in line) and not (':' in line):
                for ip in list(ipaddress.ip_network(line, False).hosts()):
                    if ip not in ips:
                        ips.append(ip)
            else:
                ips.append(ipaddress.ip_address(line))
        except ValueError:
            domains.append(line)
    return ips, domains

def run_nslookup(domain):
    '''This function extends the IPs list with a nslookup'''
    ips = []
    try :
        ips_nslookup = Nslookup().dns_lookup(domain).answer
        if not ips_nslookup:
            raise ValueError
        for ip_nslookup in ips_nslookup:
            ip = ipaddress.ip_address(ip_nslookup)
            if ip not in ips:
                ips.append(ip)
    except ValueError:
        print('No dns match for the domain {domain}. Are you sure it\'s a domain ?')
    return ips

def run_sslcompare(domains):
    '''Running sslcompare on all domains'''
    for domain in domains:
        print(f"---------Running sslcompare on {shlex.quote(domain)}---------")
        print(run_cmd(f'sslcompare {shlex.quote(domain)}').stdout)

def run_sslscan(domains):
    '''Running sslscan on all domains'''
    for domain in domains:
        print(f"---------Running sslscan on {domain}---------")
        output = run_cmd(f'sslscan {shlex.quote(domain)}').stdout
        if output:
            print(output)

def run_headerexposer(domains):
    '''Running header exposer on all domains'''
    for domain in domains:
        print(f"---------Running headerexposer on {domain}---------")
        url = 'http://'+shlex.quote(domain) if 'http' not in domain else shlex.quote(domain)
        output = run_cmd(f'headerexposer analyse {url}').stdout
        if output:
            print(output)

def run_nmaps(ips, scope, path):
    '''Running nmap on all ips concurently'''
    threads = list()
    for ip in ips:
        x = threading.Thread(target=run_nmap2, args=(ip, scope, path))
        threads.append(x)
        x.start()
        break
    for _,thread in enumerate(threads):
        thread.join()
        print("All nmaps have ended")

def run_nmap2(ip, scope, path):
    '''Running a first nmap on all port and then a more detailes and discrete one on the open ports'''
    ip = shlex.quote(format(ip))    
    output_file = f'{path}/nmap_{ip}.xml'
    command = f'nmap -sV -p- -Pn -T4 {ip} -oX {output_file}'
    
    run_cmd(command)
    root = ET.parse(output_file).getroot()

    ports = []
    for host in root.findall('host'):
        for port in host.findall('ports/port'):
            if port.find('state').get('state') == 'open':
                ports.append(int(port.get('portid')))

    if 80 in ports:
        check_http_redirect(ip, 80)
    if 8080 in ports:
        check_http_redirect(ip, 8080)
    if 8008 in ports:
        check_http_redirect(ip, 8008)

def checkIP(IP):
    '''This function checks we are doing the test from the wanted source'''
    if not IP.stdout:
        print('Please be sure you are connected (the proper use of the Lab IP could not be checked)')
        exit(1)
    if IP.stdout != '62.23.181.125':
        print('Please be sure to run your test from the Lab IP')
        exit(1)

def checkWAF(domains, IPs):
    '''This function checks the WAF that is set up'''
    for domain in domains:
        run_cmd(f'wafw00f -v -a {shlex.quote(domain)}')
    for ip in IPs:
        run_cmd(f'wafw00f -v -a http://{shlex.quote(format(ip))}')
        run_cmd(f'wafw00f -v -a https://{shlex.quote(format(ip))}')

def run_feroxbuster(domain, args_ferox, out_path):
    '''Run feroxbuster on a domain'''
    print(f"--------Fuzzing on {format(domain)} with feroxbuster--------")
    cmd=f'feroxbuster -u http://{shlex.quote(format(domain))} {shlex.quote(format(args_ferox))} -o {out_path}/ferobuster_{shlex.quote(format(domain))}.log'
    run_cmd(cmd)

def run_feroxbusters(domains, args_ferox):
    '''This function run parallelized fuzzing on the domains'''
    threads = list()
    for domain in domains:
        x = threading.Thread(target=run_feroxbuster, args=(domain,args_ferox))
        threads.append(x)
        x.start()
        break
    for _,thread in enumerate(threads):
        thread.join()
        print("All fuzzing have ended")

def main():
    '''Main function running all test one after the others'''
    args = parse()
    myIP = run_cmd('curl ifconfig.me', stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    folder_path = os.path.join(os.environ['HOME'], "Documents/Mission/out/basic_checks")
    if not os.path.exists(folder_path):
        os.makedirs(folder_path)
    if not args.force:
        checkIP(myIP)
    try :
        with open(args.scope, 'r', encoding="utf-8") as f:
            ips, domains = def_ips_domain(f)
            print(f'{str(len(ips))} IPs were found in file')
            print(f'{str(len(domains))} domain were found in file')
            print('---------,------Looking for WAF---------------')
            checkWAF(domains, ips)
            print("---------Running nslookup on domains---------")
            for domain in domains:
                ips += run_nslookup(domain)
    except FileNotFoundError:
        print("Looks like the file does not exist")
    print(ips)
    print(domains)

    #Running headerexposer
    run_headerexposer(domains)

    #Running sslcompare
    run_sslcompare(domains)
    
    #run sslscan
    run_sslscan(domains)
    
    #Checking allowed methods
    check_http_methods(domains)

    #Running nmaps
    run_nmaps(ips, args.scope, folder_path)

    #Running feroxbuster
    run_feroxbusters(domains, args.ferox_args, folder_path)

    print('DONE')

if __name__=='__main__':
    main()
