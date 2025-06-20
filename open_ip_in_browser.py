#!/bin/python3
'''
This program opens all webpages you want to check
@authors ybeattie
'''

import webbrowser
import argparse
import random
import requests
from utils import print_error

def parse():
    '''This function defines the argument of our script'''
    parser = argparse.ArgumentParser(
        prog="open_ip_in_browser",
        description="Opens browser with all the pages provided over http and https",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    parser.add_argument("-f", "--file",
                        help="IP file (IP:Port one by line)",
                        required=True)
    parser.add_argument("-p", "--simultaneous-pages",
                        help="The number of page you want to open by wave",
                        required=False,
                        type=int,
                        default=50)
    parser.add_argument("-C", "--filter-status",
                        help="Only open status that do not returns those status (ex: -C 404,500)",
                        required=False)
    parser.add_argument("-A", "--random-useragent",
                        help="Adds random user agents to the requests every groups of pages",
                        required=False,
                        action="store_true")
    parser.add_argument("-t", "--timeout",
                        help="Timeout for get requests",
                        default=3,
                        required=False,
                        type=int)
    parser.add_argument("--proxies",
                        help="Add a proxy (--proxies 'http://127.0.0.1:8080,https://127.0.0.1:8080'). The webbrowser pages will not go through proxy.",
                        required=False,
                        type=str)
    parser.add_argument("-H", "--headers",
                        help="Add a custom header (-H 'Authorization: Bearer ey...'). Header can be used multiple times",
                        nargs=1,
                        required=False,
                        type=str)
    #parser.add_argument("-o", "--output", help="Output file", required=False)
    return parser.parse_args()

def open_urls(urls, args):
    '''This function opens a list of url in your favorite browser'''
    if args.filter_status:
        filtered_status = args.filter_status.split(',')
    else :
        filtered_status = []
    nbr_pages = args.simultaneous_pages
    headers = {}
    with open("wordlists/useragents.txt", 'r', encoding="utf-8") as f:
        if args.random_useragent :
            lines = f.readlines()
            rand = random.randint(0, len(lines)-1)
            user_agent_list = lines[rand]
            headers["User-Agent"] =user_agent_list.strip()
    if args.headers:
        try:
            for header in args.headers:
                headers[header.split(':')[0].strip()] = header.split(':')[1].strip()
        except IndexError:
            print_error("The headers you provided do not have the correct format")
    proxies = {}
    if args.proxies:
        proxy = args.proxies.split(',')
        for prox in proxy:
            proxies[prox.split('://')[0].strip()] = prox.strip()
    for url_id,url in enumerate(urls) :
        if url_id < nbr_pages:
            try:
                status = requests.get(url, timeout=int(args.timeout), headers=headers, proxies=proxies).status_code
                if status not in filtered_status:
                    webbrowser.open(url, new=2)
            except requests.exceptions.InvalidURL:
                continue
            except requests.exceptions.ReadTimeout:
                print_error(f"Timeout for {url}")
                continue
            except requests.exceptions.ConnectionError: #Typiquement requetes https sur un port 80
                print_error(f"Connection Error for {url}")
                continue
            except requests.exceptions.RetryError:
                print_error(f"MaxRetry Error for {url}")
                continue
        else:
            input(f'Press any key to open the next {nbr_pages} pages')
            open_urls(urls[nbr_pages:], args)
            break
    return 0

def main():
    '''This core function gather the ip:port given, build urls and open them'''
    args = parse()
    with open(args.file, 'r', encoding='utf-8') as f:
        ip_ports = [line.strip() for line in f.readlines()]
        urls = []
        for endpoint in ip_ports:
            if endpoint.startswith('http'):
                urls.append(endpoint)
            else:
                urls.append(f"https://{endpoint}")
                urls.append(f"http://{endpoint}")
        open_urls(urls=urls, args=args)
        print("END")

if __name__=='__main__':
    main()
