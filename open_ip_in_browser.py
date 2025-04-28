#!/bin/python3
# This program opens all webpages you want to check (by group of 20) 
# @authors ybeattie

import webbrowser
import argparse
import requests 

def parse():
    '''This function defines the argument of our script'''
    parser = argparse.ArgumentParser(
        prog="Open browser with all the pages",
        description="Basically opens http and https for all IP:Port given",
    )
    parser.add_argument("-f", "--file", help="IP file (IP:Port one by line)", required=True)
    #parser.add_argument("-o", "--output", help="Output file", required=False)
    return parser.parse_args()

def open_urls(urls):
    '''This function opens a list of url in your favorite browser'''
    for url_id in range(len(urls)) :
        if url_id < 50:
            status = requests.get(urls[url_id], timeout=2).status_code
            if status != 403 and status != 404:
                #print(requests.get(urls[url_id], timeout=2).text)
                webbrowser.open(urls[url_id], new=2)
        else:
            input('Press any key to open the next 20 pages')
            open_urls(urls[50:])
            break
    return 0

def main():
    '''This core fucntion gather the ip:port given, build urls and open them'''
    args = parse()
    with open(args.file, 'r', encoding='utf-8') as f:
        ip_ports = [line.strip() for line in f.readlines()]
        urls = ["https://"+ip_port for ip_port in ip_ports]
        open_urls(urls)
        print("END")

if __name__=='__main__':
    main()