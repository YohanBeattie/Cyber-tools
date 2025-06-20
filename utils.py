#!/bin/python3
'''
This program gather all useful and transverse functions
@authors ybeattie
'''

import subprocess
from os import devnull
from os import environ
import yaml

class Bcolors:
    '''Class defining the colors of the prints'''
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'

def signal_handler():
    '''Catch user interruption and cleans before stopping'''
    print('You pressed Ctrl+C, cleaning...')
    clean()
    print('Exiting...')
    exit(0)

def setvariables(reset=False):
    '''Sets API keys as variables'''
    with open("conf.yaml", "r", encoding="utf-8") as config:
        config = yaml.safe_load(config)
        for _, (key, value) in enumerate(config["api_keys"].items()):
            if reset :
                environ[key] = ''
            else:
                environ[key] = value

def clean():
    '''Unsets all API_keys on interruptions'''
    setvariables(reset=True)

def print_info(info):
    '''Special function to print some info'''
    print(Bcolors.OKBLUE + f'[INFO] {info}' + Bcolors.ENDC)

def print_error(error):
    '''Special function to print some error'''
    print(Bcolors.FAIL + f'[ERROR] {error}' + Bcolors.ENDC)

def print_success(msg):
    '''Special function to print some sucess message'''
    print(Bcolors.OKGREEN + f'[+] {msg}' + Bcolors.ENDC)

def print_warning(warn):
    '''Special function to print a warning'''
    print(Bcolors.WARNING + f'[-] {warn}' + Bcolors.ENDC)

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
        print_info(f'Running {cmd}')
    if silent:
        stdout=open(devnull, "wb")
    return subprocess.run(cmd.split(' '), encoding='utf-8', \
        stdout=stdout, stderr=stderr, stdin=stdin, input=myinput, check=False)
