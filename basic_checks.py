#!/bin/python3
# This program automatize basic test for web interface
# @authors ybeattie
# @version 2.0

import argparse
import os
import ipaddress
import subprocess
import shlex
import threading
import xml.etree.ElementTree as ET
from nslookup import Nslookup
from utils import run_cmd

def parse():
    '''This function defines the argument of our script'''
    parser = argparse.ArgumentParser(
        prog="Basic checks for web pentests",
        description="Those checks include nmap, ssl and header checks & fuzzing,...",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    parser.add_argument("-f", "--scope", required=True,\
        help="Scope file (IP range, IP addresse, domains)")
    parser.add_argument("--force", action="store_true", required=False,
        help="Force script to execute (even without Lab-IP)")
    parser.add_argument("--ferox-args", required=False,
        help="Argument provided to the fuzzing part. See 'feroxbuster -h' for felp",
        default='--smart -C 404 --thorough -r -w /usr/share/wordlists/SecLists/Discovery/Web-Content/raft-medium-files.txt')
    parser.add_argument("-o", "--output", help="Output logs location", default="Documents/Mission/out/basic_checks", required=False)
    return parser.parse_args()

def check_http_methods(domains):
    ''' Checks http methods with nmap (not great)'''
    for domain in domains:
        print(f'Checking the autorized methods on {domain}')
        run_cmd(f'nmap --script http-methods {shlex.quote(domain)}')

def check_http_redirect(ip, port):
    ''' Checks if the http port redirects to https'''
    print(f"Checking if http request on {ip} redirects to https")
    run_cmd(f'curl http://{shlex.quote(ip)}:{shlex.quote(port)}')

def def_ips_domain(file):
    '''This function defines our scope based on the input file'''
    ips = []
    domains = []
    for line in file.readlines():
        line = line.strip()
        try:
            if ('-' in line or '/' in line) and not ':' in line:
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

def run_nmaps(ips, path):
    '''Running nmap on all ips concurently'''
    threads = list()
    for ip in ips:
        x = threading.Thread(target=run_nmap2, args=(ip, path))
        threads.append(x)
        x.start()
        break
    for _,thread in enumerate(threads):
        thread.join()
        print("All nmaps have ended")

def run_nmap2(ip, path):
    '''Running nmap and checking http redirection'''
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

def check_ip(ip):
    '''This function checks we are doing the test from the wanted source'''
    if not ip.stdout:
        print('Please be sure you are connected (the use of the correct IP could not be checked)')
        exit(1)
    if ip.stdout != '62.23.181.125':
        print('Please be sure to run your test from the Lab IP')
        exit(1)

def check_waf(domains, ips):
    '''This function checks the WAF that is set up'''
    for domain in domains:
        run_cmd(f'wafw00f -v -a {shlex.quote(domain)}')
    for ip in ips:
        run_cmd(f'wafw00f -v -a http://{shlex.quote(format(ip))}')
        run_cmd(f'wafw00f -v -a https://{shlex.quote(format(ip))}')

def run_feroxbuster(domain, args_ferox, out_path):
    '''Run feroxbuster on a domain'''
    print(f"--------Fuzzing on {format(domain)} with feroxbuster--------")
    args_ferox = args_ferox
    print(args_ferox)
    domain = shlex.quote(format(domain))
    cmd=f'feroxbuster -u http://{domain} {args_ferox} -o {out_path}/ferobuster_{domain}.log'
    run_cmd(cmd)

def run_feroxbusters(domains, args_ferox, path):
    '''This function run parallelized fuzzing on the domains'''
    threads = list()
    for domain in domains:
        x = threading.Thread(target=run_feroxbuster, args=(domain,args_ferox, path))
        threads.append(x)
        x.start()
        break
    for _,thread in enumerate(threads):
        thread.join()
        print("All fuzzing have ended")

def main():
    '''Main function running all test one after the others'''
    args = parse()
    folder_path = os.path.join(os.environ['HOME'], args.output)
    if not os.path.exists(folder_path):
        os.makedirs(folder_path)
    if not args.force:
        my_ip = run_cmd('curl ifconfig.me', stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        check_ip(my_ip)
    try :
        with open(args.scope, 'r', encoding="utf-8") as f:
            ips, domains = def_ips_domain(f)
            print(f'{str(len(ips))} IPs were found in file')
            print(f'{str(len(domains))} domain were found in file')
            print('---------,------Looking for WAF---------------')
            check_waf(domains, ips)
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
    #check_http_methods(domains)

    #Running nmaps
    run_nmaps(ips, folder_path)

    #Running feroxbuster
    run_feroxbusters(domains, args.ferox_args, folder_path)

    print('DONE')

if __name__=='__main__':
    main()
