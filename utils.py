#!/bin/python3
'''
This program gather all useful and transverse functions
@authors ybeattie
'''

import subprocess
from os import devnull

class bcolors:
    '''Class defining the colors of the prints'''
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'

def printInfo(info):
    '''Special function to print some info'''
    print(bcolors.OKBLUE + f'[INFO] {info}' + bcolors.ENDC)

def printError(error):
    '''Special function to print some error'''
    print(bcolors.FAIL + f'[ERROR] {error}' + bcolors.ENDC)

def printSuccess(msg):
    '''Special function to print some sucess message'''
    print(bcolors.OKGREEN + f'[+] {msg}' + bcolors.ENDC)

def printWarning(warn):
    '''Special function to print a warning'''
    print(bcolors.WARNING + f'[-] {warn}' + bcolors.ENDC)

def load_wordlist(file_path):
    '''Function transforming a file into a list'''
    tenants = set()
    with open(file_path, 'r', encoding='utf-8') as f:
        for line in f.readlines():
            tenants.add(line.strip().lower())
    return tenants

def run_cmd(cmd, stdin=None, stdout=None, stderr=None, silent=False, myprint=True, myinput=None):
    ''' This is a special function for running bash cmd and printing or not de result
    WARNING : Please be sure to rightfully treat the input '''
    if myprint :
        printInfo(f'Running {cmd}')
    if silent:
        stdout=open(devnull, "wb")
    return subprocess.run(cmd.split(' '), encoding='utf-8', \
        stdout=stdout, stderr=stderr, stdin=stdin, input=myinput, check=False)
