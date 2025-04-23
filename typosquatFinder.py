#!/bin/python3
# Test automatisé utils en reconnaissance externe et typosquatting
# @authors ybeattie

import argparse

def parse():
    '''This function defines the argument of our script'''
    parser = argparse.ArgumentParser(
        prog="Looking for typosquatters and domains",
        description="Looks for typosquatters using microsoft tenants, aws buckets, shodan or favicorn",
    )
    parser.add_argument("-k", "--keyword", help="Keywords or domain to search for", required=True)
    #parser.add_argument("-o", "--output", help="Output file", required=False)
    return parser.parse_args()

import requests
from tld import get_tld
from tld.exceptions import TldDomainNotFound

def generate_typos(domain):
    try:
        tld = get_tld(f"http://{domain}", as_object=True)
        name = domain[:-(len(tld.tld) + 1)]  # remove TLD and dot
    except TldDomainNotFound:
        # If TLD is not recognized, assume the last part is the TLD
        parts = domain.split('.')
        if len(parts) > 1:
            name = '.'.join(parts[:-1])
            tld = parts[-1]
        else:
            # If there's no dot, treat the whole string as the name
            name = domain
            tld = ''
    
    typos = []
    
    # Common typos
    keyboards = {
        'qwerty': {
            'q': 'wa', 'w': 'qes', 'e': 'wrd', 'r': 'eft', 't': 'rgy',
            'y': 'thu', 'u': 'yij', 'i': 'uok', 'o': 'ipl', 'p': 'o',
            'a': 'qwsz', 's': 'awedxz', 'd': 'serfcx', 'f': 'drtgvc', 'g': 'ftyhbv',
            'h': 'gyujnb', 'j': 'huikmn', 'k': 'jiolm', 'l': 'kop',
            'z': 'asx', 'x': 'zsdc', 'c': 'xdfv', 'v': 'cfgb', 'b': 'vghn', 'n': 'bhjm', 'm': 'njk'
        }
    }
    
    # Generate typos
    for i, c in enumerate(name):
        for adj in keyboards['qwerty'].get(c.lower(), ''):
            typos.append(name[:i] + adj + name[i+1:])
    
    # Omissions
    for i in range(len(name)):
        typos.append(name[:i] + name[i+1:])
    
    # Duplications
    for i in range(len(name)):
        typos.append(name[:i] + name[i] + name[i:])
    
    # Transpositions
    for i in range(len(name)-1):
        typos.append(name[:i] + name[i+1] + name[i] + name[i+2:])
    
    # Alt encodings (ASCII )
    alternatives = {'s': '5', 'l': '1', 'o': '0', 'a': '4', 'e': '3', 'i': '1', 't': '7'}
    for i, c in enumerate(name):
        if c.lower() in alternatives:
            typos.append(name[:i] + alternatives[c.lower()] + name[i+1:])
    
    # Add the TLD back to the typos
    if tld:
        return [f"{typo}.{tld}" for typo in set(typos)]
    else:
        return list(set(typos))
    
def check_tenant_exists(tenant_name):
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

def load_wordlist(file_path):
    tenants = set()
    with open(file_path, 'r') as f:
        for line in f:
            line = line.strip()
            if line:
                tenants.add(line.lower())
    return tenants

def main():
    wordlist_path = "wordlist6.txt"  # Ex: contient juste "micros0ft", "m1crosoft"
    tenants = load_wordlist(wordlist_path)
    print(f"🕵️ Vérification de {len(tenants)} tenants...\n")
    for tenant in tenants:
        result = check_tenant_exists(tenant)
        domain = f"{tenant}.onmicrosoft.com"
        if result is True:
            print(f"[✅] {domain} existe")
        elif result is False:
            #print(f"[❌] {domain} n'existe pas")
            pass
        else:
            print(f"[⚠️] Erreur ou indéterminé pour {domain}")

def builtTypoDoms(keywords):
    with open ('common_TLDs.txt', 'r', encoding='utf-8') as g:
        domains =[]
        for keyword in keywords:
            domains += generate_typos(keyword)
        domains = [[domi.split('.')[0]+'.'+ tld for domi in domains] for tld in g.readlines()]


def searchMicrosoftTenants(keyword):
    return 0


def searchShodanMention(keyword):
    return 0

def searchBucketAWS(keyword):
    return 0

def searchSameFavicon(keyword):
    return 0

def main():
    '''Unifing all the search engines'''
    return 0


if __name__=='__main__':
    main()