#!/bin/python3
'''
Test automatisé utils en reconnaissance externe et typosquatting
@authors ybeattie
'''

import argparse
from os.path import exists
import sys
import traceback
from queue import Queue
from threading import Thread
import shlex
from subprocess import PIPE
import requests
import xmltodict
from utils import load_wordlist, printInfo, printSuccess, printError,run_cmd
from generate_typos import builtTypoDoms
import subprocess

def parse():
    '''This function defines the argument of our script'''
    parser = argparse.ArgumentParser(
        prog="typosquatFinder",
        description="Looks for typosquatters using microsoft tenants, \
            aws buckets, shodan and favicorn",
    )
    parser.add_argument("-k", "--keywords", help="Keywords or domain to search for", required=True)
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

def searchMicrosoftTenants(wordlist_path):
    '''This function checks if a corresponding tenants exists for each domain given'''
    printInfo("Searching for Micorosft Tenants' typosquatters")
    tenants = load_wordlist(wordlist_path)
    printInfo(f"🕵️ Vérification de {len(tenants)} tenants...\n")
    for tenant in tenants:
        result = check_tenant_exists(tenant)
        domain = f"{tenant}.onmicrosoft.com"
        if result is True:
            printSuccess(f"{domain} existe")
    return 0

bucket_q = Queue()
download_q = Queue()
url404 = []

def fuzzing(url_list, wordlist):
    '''Fuzzing all domain aws to find files'''
    for url in url_list:
        '''ps = subprocess.Popen(("feroxbuster", "-u", url, "-t", "20", "-C", "403,500,503", "-k", "-w", shlex.quote(wordlist), "--dont-scan", "soap"), stdout=subprocess.PIPE)
        output = subprocess.check_output(('sed', '/^$/d'), stdin=ps.stdout)
        ps.wait()
        '''
        with open('ferox_output.log', 'w', encoding='utf-8') as f: # this could be bugged by parallèle scan
            ps = run_cmd(f"feroxbuster -u {url} -t 20 -C 403,500,503 -k --silent -w {shlex.quote(wordlist)} --dont-scan soap", stdout=PIPE, silent=True)
            run_cmd(f"awk NF ", myinput=ps.stdout, silent=True)


def fetchAWS(url):
    ''' Function requesting the url to check if bucket is accessible'''
    response = requests.get(url, timeout=5)
    if response.status_code == 403 or response.status_code == 404:
        #print(f'404 : {url}. Still trying fuzzing...')
        url404.append(url)
    elif response.status_code == 200:
        printSuccess(f'200 : {url}')
        if "Content" in response.text:
            status200AWS(response, url)

def bucket_workerAWS():
    '''Creating a bucket working'''
    while True:
        item = bucket_q.get()
        try:
            fetchAWS(item)
        except Exception as e:
            traceback.print_exc(file=sys.stdout)
            printError(e)
        bucket_q.task_done()

def status200AWS(response, line):
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

def searchBucketAWS(keywords):
    '''AWS main function looking for AWS buckets'''
    printInfo('Buckets will not be downloaded')
    # start up bucket workers
    for _ in range(0, 5): # 5 being the number of thread
        t = Thread(target=bucket_workerAWS)
        t.daemon = True
        t.start()

    with open(keywords, 'r', encoding='utf-8') as f:
        for line in f:
            bucket = 'http://'+line.rstrip()+'.s3.amazonaws.com'
            bucket_q.put(bucket)

    bucket_q.join()
    return 0

def searchSameFavicon(keyword):
    return 0

def searchShodanMention(keyword):
    return 0

def searchBlackHatWarfare(keyword): # ?
    return 0

def main():
    '''Unifing all the search engines'''
    #Generating typos
    args = parse()
    if exists(args.keywords): # Checks if the input is an existing file
        printInfo('Input file detected')
        keywords = load_wordlist(args.keywords)
    else :
        printInfo('Keyword input detected')
        keywords = [args.keywords]
    wordlist_path = builtTypoDoms(keywords=keywords)
    printInfo("Searching for Microsoft Tenants")
    #searchMicrosoftTenants(wordlist_path=wordlist_path)
    printInfo("Searching AWS buckets")
    searchBucketAWS(keywords=wordlist_path)
    printInfo('Running fuzzing on all urls for AWS buckets(even 404)')
    with open('tmp.txt', 'r', encoding='utf-8') as f:
        tmp_url = []
        for url in f.readlines():
            tmp_url.append(url.strip())
    fuzzing(url404, "/usr/share/SecLists/Discovery/Web-Content/quickhits.txt")
    return 0


if __name__=='__main__':
    main()
