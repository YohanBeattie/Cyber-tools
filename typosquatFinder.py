#!/bin/python3
'''
Tests automatisés pour de la reconnaissance externe et recherche de typosquatting
@authors ybeattie
TODO : add loading bar on Tenants, Buckets, and favicon ?
'''

import argparse
from os.path import exists
from signal import signal, SIGINT
from queue import Queue
from threading import Thread
import shlex
from subprocess import PIPE
import requests
import xmltodict
from rich.progress import Progress
import utils
from typoScripts.generate_typos import built_typo_domains

def parse():
    '''This function defines the argument of our script'''
    parser = argparse.ArgumentParser(
        prog=" typosquat_finder",
        description="Looks for typosquatters using microsoft tenants, \
            aws buckets, shodan and favicorn",
    )
    parser.add_argument("-d", "--domains", help="Input files must contain domains or be a domain",
                        required=True)
    parser.add_argument("-v", "--verbose",
                        help="Add verbosity to the output",
                        action="store_true",
                        required=False)
    parser.add_argument("-w", "--wordlist",
                        help="A wordlist for fuzzing on aws bucket",
                        default="/usr/share/SecLists/Discovery/Web-Content/quickhits.txt",
                        required=False)
    parser.add_argument("--fuzz",
                        help="Fuzz on aws tenants even if the bucket returns à 404 status code",
                        action="store_true")
    parser.add_argument("--t", "threads",
                        help="Defines the number of threads",
                        default=5, type=int)
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
    utils.print_info("Searching for Micorosft Tenants' typosquatters")
    tenants = utils.load_wordlist(wordlist_path)
    utils.print_info(f"🕵️ Checking on {len(tenants)} tenants...\n")
    for tenant in tenants:
        result = check_tenant_exists(tenant)
        domain = f"{tenant}.onmicrosoft.com"
        if result is True:
            utils.print_success(f"{domain} exist")
        elif VERBOSE:
            utils.print_warning(f"{domain} do not exist")
    return 0

bucket_q = Queue()
download_q = Queue()
url404 = []
VERBOSE = False

def fuzzing(url_list, wordlist):
    '''Fuzzing all domain aws to find files'''
    for url in url_list:
        url = shlex.quote(url)
        ps = utils.run_cmd(f"feroxbuster -u {url} -t 20 -C 403,500,503 -k -W 0 \
                           --silent -w {shlex.quote(wordlist)} --dont-scan soap \
                            --filter-similar-to {url} --filter-similar-to {url}/%ff/",
                            stdout=PIPE, myprint=VERBOSE)
        utils.run_cmd("awk NF ", myinput=ps.stdout, myprint=False)

def fetch_aws(url):
    ''' Function requesting the url to check if bucket is accessible'''
    try :
        response = requests.get(url, timeout=5)
        if response.status_code == 403 or response.status_code == 404:
            url404.append(url)
        elif response.status_code == 200:
            utils.print_success(f'200 : {url}')
            if "Content" in response.text:
                status200_aws(response, url)
    except requests.exceptions.RequestException as e:
        utils.print_error(f'Fetching on amazonaws.com raised an error : {e}')

def bucket_worker_aws():
    '''Creating a bucket working'''
    while True:
        item = bucket_q.get()
        fetch_aws(item)
        bucket_q.task_done()

def status200_aws(response, line):
    '''Function called when a bucket is existing. Checks keys'''
    utils.print_success("Found bucket. Pilfering "+line.rstrip() + '...')
    objects = xmltodict.parse(response.text)
    keys = []
    try:
        contents = objects['ListBucketResult']['Contents']
        if not isinstance(contents, list):
            contents = [contents]
        for child in contents:
            keys.append(child['Key'])
    except KeyError:
        pass
    utils.print_info(f"Found keys : {str(keys)}")

def thread_work(my_function, domains_file, thread_number):
    '''Used to speed up function run using urls'''
    for _ in range(0, thread_number): 
        t = Thread(target=my_function)
        t.daemon = True
        t.start()
    with open(domains_file, 'r', encoding='utf-8') as f:
        with Progress() as p:
            t = p.add_task("Processing...", total=len(f.readlines()))   
            for line in f.readlines():
                bucket_q.put(line.rstrip())
                p.update(t, advance=1)
    bucket_q.join()
    return 0

def search_bucket_aws(keywordsfile, thread_number):
    '''AWS main function looking for AWS buckets'''
    utils.print_info('Buckets will not be downloaded')
    # start up bucket workers
    urls_path = "tmp/aws_urls.txt"
    with open(urls_path, 'w', encoding='utf-8') as aws_urls:
        with open(keywordsfile, 'r', encoding='utf-8') as f:
            for line in f.readlines():
                aws_urls.write('http://'+line.rstrip()+'.s3.amazonaws.com')
    thread_work(bucket_worker_aws, urls_path, thread_number)

def search_same_favicon(domains):
    '''This function search for domain based on the favicon'''
    utils.setvariables()
    assets = []
    for domain in domains:
        domain = shlex.quote(domain)
        fav_file = f"tmp/{domain}_favicorn.out"
        with open(fav_file, "w", encoding='utf-8') as f:
            utils.run_cmd(f"python3 typoScripts/favicorn.py --no-logo -d {domain}", stdout=f)
        with open(fav_file, "r", encoding='utf-8') as g:
            try:
                results = g.readlines()[-1].split('/')[-1].strip()
                if "ICO file of favicon" in results:
                    utils.print_warning(f"No favicon could be extracted for {domain}")
                else:
                    with open(f'{results}', 'r', encoding='utf-8') as h:
                        lines = h.readlines()
                        if len(lines):
                            assets += lines
                        else:
                            utils.print_warning("The favicon search did not provide any results")
            except IndexError:
                utils.print_error(f'No results in reverse search favicon for {domain}')
    if assets:
        utils.print_success("The favicon search revealed the following domains :")
        with open('favicon.domains', 'a', encoding='utf-8') as f:
            for asset in list(set(assets)):
                print(asset.strip())
                f.write(asset.strip())
    return 0

def check_website(domain):
    '''Checks if a typosquatted domain exists'''
    try:
        r = requests.get(domain, timeout=10)
        utils.print_success(f"A similar website was found : {domain} (status:{r.status_code})")
    except requests.exceptions.ConnectionError:
        pass
    except requests.exceptions.ReadTimeout:
        utils.print_info(f"Connection timeout on {domain}")

def check_websites(domainsfile, thread_number):
    '''Check if typosquatting website are up'''
    urls_path = "out/website_typosquat.txt"
    with open(domainsfile, 'r', encoding='utf-8') as domains:
        with open(urls_path, "w", encoding="utf-8") as f:
            for domain in domains.readlines():
                f.write('http://'+domain.strip())
    thread_work(check_website, urls_path, thread_number=thread_number)

def search_shodan_mention(keywords):
    ''' Using shodan to find results on typosquatters'''
    return 0

def search_blackhat_warfare(keywords): # ?
    ''' Use blackhat to find results on typoquatters'''
    return 0

def main():
    '''Unifing all the search engines'''
    #Generating typos
    global VERBOSE
    signal(SIGINT, utils.signal_handler)
    args = parse()
    if exists(args.domains): # Checks if the input is an existing file
        utils.print_info('Input file detected')
        keywords = utils.load_wordlist(args.domains)
    else :
        utils.print_info('Keyword input detected')
        keywords = [args.domains]
    wordlist_path = built_typo_domains(keywords=keywords)
    check_websites(domainsfile=wordlist_path, thread_number=args.threads)
    if VERBOSE:
        utils.print_info("Verbose option selected")
    VERBOSE = True if args.verbose else False
    utils.print_info("Searching for Microsoft Tenants")
    search_microsoft_tenants(wordlist_path=wordlist_path)
    utils.print_info("Searching AWS buckets")
    search_bucket_aws(keywordsfile=keywords, thread_number=args.treads)
    if args.fuzz:
        utils.print_info('Running fuzzing on all urls for AWS buckets(even 404)')
        fuzzing(url404, args.wordlist)
    utils.print_info('Searching for new domain using favicon')
    search_same_favicon(domains=keywords)
    utils.print_info('All new domains were append to the file favicon.domains')
    return 0

if __name__=='__main__':
    main()
