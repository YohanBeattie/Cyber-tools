#!/usr/bin/env python
# Inspired from AWSBucketDump github from @JordanPotti

from argparse import ArgumentParser
import requests
import xmltodict
import sys
import os
import shutil
import traceback
from queue import Queue
from threading import Thread, Lock
from utils import printInfo,printError,printSuccess,printWarning

bucket_q = Queue()
download_q = Queue()

def parse():
    '''This function defines the argument of our script'''
    parser = ArgumentParser(
        prog="tmp_aws_beckets",
    description="Bruteforce looking for existing AWS Buckets either for typosquatters id or simply publicaly expose buckets",
    )
    parser.add_argument("-t", "--targets", help="Target file with domains or keywords", required=True)
    #parser.add_argument("-o", "--output", help="Output file", required=False)
    return parser.parse_args()
    
def fetch(url):
    ''' Function requesting the url to check if bucket is accessible'''
    response = requests.get(url)
    if response.status_code == 403 or response.status_code == 404:
        pass
    elif response.status_code == 200:
        if "Content" in response.text:
            status200(response, url)

def bucket_worker():
    '''Creating a bucket working'''
    while True:
        item = bucket_q.get()
        try:
            fetch(item)
        except Exception as e:
            traceback.print_exc(file=sys.stdout)
            printError(e)
        bucket_q.task_done()

def status200(response, line):
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

def main():
    args = parse()

    printInfo('Buckets will not be downloaded')
    # start up bucket workers
    for _ in range(0, 5): # 5 being the number of thread 
        t = Thread(target=bucket_worker)
        t.daemon = True
        t.start()

    with open(args.targets) as f:
        for line in f:
            bucket = 'http://'+line.rstrip()+'.s3.amazonaws.com'
            bucket_q.put(bucket)

    bucket_q.join()
    print('END')

if __name__ == "__main__":
    main()