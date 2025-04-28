#!/bin/python3
# This program gather all useful and transverse function
# @authors ybeattie

import subprocess

class bcolors:
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'

def printInfo(info):
    print(bcolors.OKBLUE + f'[INFO] {info}' + bcolors.ENDC)

def printError(error):
    print(bcolors.FAIL + f'[ERROR] {error}' + bcolors.ENDC)

def printSuccess(msg):
    print(bcolors.OKGREEN + f'[+] {msg}' + bcolors.ENDC)

def printWarning(warn):
    print(bcolors.WARNING + f'[-] {warn}' + bcolors.ENDC)

def run_cmd(cmd, stdout=None, stderr=None):
    ''' This is a special function for running bash cmd and printing or not de result '''
    ''' WARNING : Please be sure to rightfully treat the input '''
    printInfo(f'Running {cmd}')
    return subprocess.run(cmd.split(' '), encoding='utf-8', \
        stdout=stdout, stderr=stderr, check=False)