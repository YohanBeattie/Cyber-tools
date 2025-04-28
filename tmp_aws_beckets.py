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
    
    response = requests.get(url)
    if response.status_code == 403 or response.status_code == 404:
        pass
    elif response.status_code == 200:
        if "Content" in response.text:
            status200(response, url)


def bucket_worker():
    while True:
        item = bucket_q.get()
        try:
            fetch(item)
        except Exception as e:
            traceback.print_exc(file=sys.stdout)
            printError(e)
        bucket_q.task_done()

def downloadWorker():
    while True:
        item = download_q.get()
        try:
            downloadFile(item)
        except Exception as e:
            traceback.print_exc(file=sys.stdout)
            printError(e)
        download_q.task_done()

directory_lock = Lock()

def get_directory_lock():
    directory_lock.acquire()

def release_directory_lock():
    directory_lock.release()


def get_make_directory_return_filename_path(url):
    bits = url.split('/')
    directory = False
    for i in range(2,len(bits)-1):
        directory = os.path.join(directory, bits[i])
    try:
        get_directory_lock()
        if not os.path.isdir(directory):
            os.makedirs(directory)
    except Exception as e:
        traceback.print_exc(file=sys.stdout)
        printError(e)
    finally:
        release_directory_lock()

    return os.path.join(directory, bits[-1]).rstrip()

interesting_file_lock = Lock()

def get_interesting_file_lock():
    interesting_file_lock.acquire()

def release_interesting_file_lock():
    interesting_file_lock.release()


def write_interesting_file(filepath):
    try:
        get_interesting_file_lock()
        with open('interesting_file.txt', 'ab+') as interesting_file:
            interesting_file.write(filepath.encode('utf-8'))
            interesting_file.write('\n'.encode('utf-8'))
    finally:
        release_interesting_file_lock()

def downloadFile(filename):
    printInfo('Downloading {}'.format(filename) + '...')
    local_path = get_make_directory_return_filename_path(filename)
    local_filename = (filename.split('/')[-1]).rstrip()
    printInfo('local {}'.format(local_path))
    if local_filename =="":
        printInfo("Directory..\n")
    else:
        r = requests.get(filename.rstrip(), stream=True)
        if 'Content-Length' in r.headers:
            if int(r.headers['Content-Length']) > 4096:
                printInfo("This file is greater than the specified max size... skipping...\n")
            else:
                with open(local_path, 'wb') as f:
                    shutil.copyfileobj(r.raw, f)
        r.close()


def queue_up_download(filepath):
    download_q.put(filepath)
    printInfo('Collectable: {}'.format(filepath))
    write_interesting_file(filepath)


def status200(response, line):
    printSuccess("Pilfering "+line.rstrip() + '...')
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
    for words in Keys:
        words = (str(words)).rstrip()
        collectable = line+'/'+words
        queue_up_download(collectable)

def main():
    args = parse()

    printInfo('Buckets will not be downloaded')
    # start up bucket workers
    for _ in range(0, 5): # 5 being the number of thread 
        t = Thread(target=bucket_worker)
        t.daemon = True
        t.start()

    for i in range(0, 5):
        t = Thread(target=downloadWorker)
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