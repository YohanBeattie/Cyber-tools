#!/bin/python3
'''
Test automatisé utils en reconnaissance externe et typosquatting
@authors ybeattie
'''

import argparse
from os.path import exists
from sys import stdout
from signal import signal, SIGINT
import traceback
from queue import Queue
from threading import Thread
import shlex
from subprocess import PIPE
import requests
import xmltodict
from utils import load_wordlist, printInfo, printSuccess, printError,run_cmd, printWarning, signal_handler, setvariables
from generate_typos import builtTypoDoms

def parse():
    '''This function defines the argument of our script'''
    parser = argparse.ArgumentParser(
        prog="typosquatFinder",
        description="Looks for typosquatters using microsoft tenants, \
            aws buckets, shodan and favicorn",
    )
    parser.add_argument("-k", "--keywords", help="Keywords or domain to search for", required=True)
    parser.add_argument("-v", "--verbose", help="Add verbosity to the output", action="store_true", required=False)
    parser.add_argument("-w", "--wordlist", help="A wordlist for fuzzing on aws bucket", default="/usr/share/SecLists/Discovery/Web-Content/quickhits.txt", required=False)
    parser.add_argument("-f", "--fuzz", help="Fuzz on aws tenants even if the bucket returns à 404 status code", action="store_true")
    #parser.add_argument("-o", "--output", help="Output file", required=False)
    return parser.parse_args()

def check_tenant_exists(tenant_name):
    '''This function checks the existent of a Micosoft Tenants'''
    url = f"https://login.microsoftonline.com/{tenant_name}/v2.0/.well-known/openid-configuration"
    try:
        response = requests.get(url, timeout=5)
        if response.status_code == 200:
            return True
        elif "AADSTS90002" in response.text:
            return False
        else:
            return None
    except requests.exceptions.RequestException:
        return None

def search_microsoft_tenants(wordlist_path):
    '''This function checks if a corresponding tenants exists for each domain given'''
    printInfo("Searching for Micorosft Tenants' typosquatters")
    tenants = load_wordlist(wordlist_path)
    printInfo(f"🕵️ Checking on {len(tenants)} tenants...\n")
    for tenant in tenants:
        result = check_tenant_exists(tenant)
        domain = f"{tenant}.onmicrosoft.com"
        if result is True:
            printSuccess(f"{domain} exist")
        elif VERBOSE:
            printWarning(f"{domain} do not exist")
    return 0

bucket_q = Queue()
download_q = Queue()
url404 = []
VERBOSE = False

def fuzzing(url_list, wordlist):
    '''Fuzzing all domain aws to find files'''
    for url in url_list:
        url = shlex.quote(url)
        ps = run_cmd(f"feroxbuster -u {url} -t 20 -C 403,500,503 -k -W 0 --silent -w {shlex.quote(wordlist)} \
                     --dont-scan soap --filter-similar-to {url} --filter-similar-to {url}/%ff/", stdout=PIPE, myprint=VERBOSE)
        run_cmd("awk NF ", myinput=ps.stdout, myprint=False)

def fetch_aws(url):
    ''' Function requesting the url to check if bucket is accessible'''
    response = requests.get(url, timeout=5)
    if response.status_code == 403 or response.status_code == 404:
        url404.append(url)
    elif response.status_code == 200:
        printSuccess(f'200 : {url}')
        if "Content" in response.text:
            status200_aws(response, url)

def bucket_worker_aws():
    '''Creating a bucket working'''
    while True:
        item = bucket_q.get()
        try:
            fetch_aws(item)
        except Exception as e:
            traceback.print_exc(file=stdout)
            printError(e)
        bucket_q.task_done()

def status200_aws(response, line):
    '''Function called when a bucket is existing. Checks keys'''
    printSuccess("Found bucket. Pilfering "+line.rstrip() + '...')
    objects = xmltodict.parse(response.text)
    Keys = []
    try:
        contents = objects['ListBucketResult']['Contents']
        if not isinstance(contents, list):
            contents = [contents]
        for child in contents:
            Keys.append(child['Key'])
    except KeyError:
        pass
    printInfo(f"Found keys : {str(Keys)}")

def search_bucket_aws(keywords):
    '''AWS main function looking for AWS buckets'''
    printInfo('Buckets will not be downloaded')
    # start up bucket workers
    for _ in range(0, 5): # 5 being the number of thread
        t = Thread(target=bucket_worker_aws)
        t.daemon = True
        t.start()

    with open(keywords, 'r', encoding='utf-8') as f:
        for line in f:
            bucket = 'http://'+line.rstrip()+'.s3.amazonaws.com'
            bucket_q.put(bucket)

    bucket_q.join()
    return 0

def searchSameFavicon(domains):
    '''This function search for domain based on the favicon'''
    setvariables()        
    for domain in domains:
        domain = shlex.quote(domain)
        with open(f"{domain}_favicorn.out", "w", encoding='utf-8') as f:
            run_cmd(f"python3 imports/favicorn.py --no-logo -d {domain}", stdout=f, myprint=False)
        with open(f"{domain}_favicorn.out", "r", encoding='utf-8') as f:
            results = f.readlines()[-1].split('/')[-1].strip()
            if results :
                printInfo(f"Based on the favicon, new sources were found. Please check api_responses for more details")
                for line in results:
                    printInfo(f"{line.strip()}")
            else:
                printInfo("No results with favicon search")
    return 0

def searchShodanMention(keyword):
    return 0

def searchBlackHatWarfare(keyword): # ?
    return 0

def main():
    '''Unifing all the search engines'''
    #Generating typos
    global VERBOSE
    signal(SIGINT, signal_handler)
    args = parse()
    if exists(args.keywords): # Checks if the input is an existing file
        printInfo('Input file detected')
        keywords = load_wordlist(args.keywords)
    else :
        printInfo('Keyword input detected')
        keywords = [args.keywords]
    #wordlist_path = builtTypoDoms(keywords=keywords)
    if VERBOSE:
        printInfo("Verbose option selected")
    VERBOSE = True if args.verbose else False
    printInfo("Searching for Microsoft Tenants")
    #search_microsoft_tenants(wordlist_path=wordlist_path)
    printInfo("Searching AWS buckets")
    #search_bucket_aws(keywords=wordlist_path)
    printInfo('Running fuzzing on all urls for AWS buckets(even 404)')
    if args.fuzz:
        fuzzing(url404, args.wordlist)
    printInfo('Searching for new domain using favicon')
    searchSameFavicon(domains=keywords)
    return 0


if __name__=='__main__':
    main()
