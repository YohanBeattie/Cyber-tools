#!/bin/python3
'''
This program opens all webpages you want to check (by group of 20)
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
                        help="timeout for get requests",
                        default=3,
                        required=False,
                        type=int)
    #parser.add_argument("-o", "--output", help="Output file", required=False)
    return parser.parse_args()

def open_urls(urls, args):
    '''This function opens a list of url in your favorite browser'''
    if args.filter_status:
        filtered_status = args.filter_status.split(',')
    else :
        filtered_status = []
    nbr_pages = args.simultaneous_pages
    header = {}
    with open("wordlists/useragents.txt", 'r', encoding="utf-8") as f:
        if args.random_useragent :
            user_agent_list = f.readlines()[random.randint(0, len(user_agent_list)-1)]
            header={"User-Agent": user_agent_list.strip()}
    for url_id,url in enumerate(urls) :
        if url_id < nbr_pages:
            try:
                status = requests.get(url, timeout=int(args.timeout), headers=header).status_code
                if status not in filtered_status:
                    webbrowser.open(url, new=2)
            except requests.exceptions.InvalidURL:
                continue
            except requests.exceptions.ReadTimeout:
                print_error(f"Timeout for {url}")
                continue
            except requests.exceptions.ConnectionError: #Typiquement requetes https sur un port 80
                #print_error(f"Connection Error for {url}")
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
        urls = ["https://"+ip_port for ip_port in ip_ports]\
            +["http://"+ip_port for ip_port in ip_ports]
        open_urls(urls=urls, args=args)
        print("END")

if __name__=='__main__':
    main()
