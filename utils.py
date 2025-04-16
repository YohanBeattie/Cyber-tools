#!/bin/python3
# This program gather all useful and transverse function
# @authors ybeattie

import subprocess

def run_cmd(cmd, stdout=None, stderr=None):
    ''' This is a special function for running bash cmd and printing or not de result '''
    ''' WARNING : Please be sure to rightfully treat the input '''
    print(f'Running {cmd}')
    return subprocess.run(cmd.split(' '), encoding='utf-8', \
        stdout=stdout, stderr=stderr, check=False)