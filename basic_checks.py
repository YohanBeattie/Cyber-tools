#!/bin/python3
# This program is supposed to automatize basic test for web interface
# @authors ybeattie
# @version 1.0

import argparse
import ipaddress
from nslookup import Nslookup
import subprocess
import shlex
import nmap
import threading
from getpass import getpass

def parse():
    '''This function defines the argument of our script'''
    parser = argparse.ArgumentParser(
        prog="Basic checks for web pentests",
        description="Those checks include nmap, sslcompare, headerexposer, ...",
    )
    parser.add_argument("-f", "--scope", help="Scope file (IP range, IP addresse, domains)", required=True)
    parser.add_argument("--force", action="store_true", help="Force script to execute (even without Lab-IP)", required=False)
    #parser.add_argument("-o", "--output", help="Output file", required=False)
    return parser.parse_args()

def run_cmd(cmd, stdout=None, stderr=None):
    '''This is a special function for running bash cmd and printing or not de result'''
    print(f'Running {cmd}')
    return subprocess.run(cmd.split(' '), encoding='utf-8', stdout=stdout, stderr=stderr)

def check_http_methods(domains):
    for domain in domains:
        print(f'Checking the autorized methods on {domain}')
        run_cmd(f'nmap --script http-methods {domain}')

def check_http_redirect(ip):
    print(f"Checking if http request on {ip} redirects to https")
    run_cmd(f'curl http://{ip}:80')

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

def run_nmap(ip, passwd):
    '''Running a first nmap on all port and then a more detailes and discrete one on the open ports'''
    #TO ADD
    # SCAN UDP sur top ports UDP (avec --max-parallelism)
    # SCAN on sX sF ?
    # TO REMOVE : the use of password as an argument :-/
    nm = nmap.PortScanner()
    print(f"--------Scanning {format(ip)} with nmap--------")
    #Parameter oX output a XML file for msf import
    nm.scan(shlex.quote(format(ip)), arguments='-p- -T4 -Pn -oX')
    ports = []
    for port in nm[format(ip)]['tcp'].keys():
        if nm[format(ip)]['tcp'][port]["state"] == 'open':
            ports.append(port)
    print(f'Some open ports were found : {ports} (no opened port could mean we\'ve been blacklisted by the WAF)')
    print(f"--------Scanning {format(ip)} on opened ports with nmap--------")
    mycmd = f'sudo -S nmap {shlex.quote(format(ip))} -p{",".join([str(port) for port in ports])} -T3 -O -sV -oX'
    subprocess.run(mycmd, encoding='utf-8', shell=True)
    #nm.scan(shlex.quote(format(ip)), arguments=f'-p{",".join([str(port) for port in ports])} -T3 -O -sV -oX', sudo=True)
    print ('\tIP \t Port \tVersion  \t\tProduct \t\tExtra Info')
    for port in nm[format(ip)]['tcp'].keys():
        print ('%s\t %s\t %s\t %s\t %s\t' % (format(ip), port, nm[format(ip)]['tcp'][port]['version'], nm[format(ip)]['tcp'][port]['product'], nm[format(ip)]['tcp'][port]['extrainfo']))
    print()
    if 80 in ports:
        check_http_redirect(ip)

def run_nmaps(ips):
    '''Running nmap on all ips concurently'''
    threads = list()
    passwd = getpass(prompt='Please enter password (OS nmap requires root privilege) (only 1 try) : ')
    for ip in ips:
        x = threading.Thread(target=run_nmap, args=(ip,passwd))
        threads.append(x)
        x.start()
        break
    for _,thread in enumerate(threads):
        thread.join()
        print("All nmaps have ended")

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

def main():
    '''Main function running all test one after the others'''
    args = parse()
    myIP = run_cmd('curl ifconfig.me', stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    if not args.force:
        checkIP(myIP)
    try :
        with open(args.scope, 'r', encoding="utf-8") as f:
            ips, domains = def_ips_domain(f)
            print(f'{str(len(ips))} IPs were found in file')
            print(f'{str(len(domains))} domain were found in file')
            print('---------------Looking for WAF---------------')
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
    run_nmaps(ips)

    print('DONE')

if __name__=='__main__':
    main()
