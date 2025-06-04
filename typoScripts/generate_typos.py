#!/bin/python3
'''
Script générant des aléas sur la liste d'entrée
@authors ?
'''

from tld import get_tld
from tld.exceptions import TldDomainNotFound
from utils import print_info

def generate_typos(domain):
    ''' Generating typos with multiple alterations (this function was stolen from the internet)'''
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

    # Omissions
    for i in range(len(name)):
        typos.append(name[:i] + name[i+1:])

    # Duplications
    for i,_ in enumerate(name):
        typos.append(name[:i] + name[i] + name[i:])

    # Transpositions
    for i in range(len(name)-1):
        typos.append(name[:i] + name[i+1] + name[i] + name[i+2:])

    # Alt encodings (ASCII )
    alternatives = {'s': '5', 'l': '1', 'o': '0', 'a': '4',
                    'e': '3', 'i': '1', '@':'a',
                    '!':'1'} 
    alternatives_cyrillic = { 'a':'а', 'c':'с', 'd':'ԁ',
                    'e':'е', 'h':'һ', 'i':'і', 'j':'ј',
                    'k':'ҟ', 'l':'ӏ', 'm':'м', 'n':'п',
                    'o':'о', 'p':'р', 'q':'ԛ', 'r':'г',
                    's':'ѕ', 'u':'џ', 'w':'ԝ', 'x':'х', 'y':'у'}
    
    typos += create_alternatives(name, alternatives)
    typos += create_alternatives(name, alternatives_cyrillic)
    
    # Add the TLD back
    if tld:
        return [f"{typo}.{tld}" for typo in set(typos)]
    else:
        return list(set(typos))

def create_alternatives(word, alternative):
    '''Creates variation in words (replace a by @ or latin letters by there cyrillic equivalent)'''
    for i, c in enumerate(word):
        if c.lower() in alternative:
            new_word = word[:i] + alternative[c.lower()] + word[i+1:]
            return [new_word]+create_alternatives(new_word, alternative)

def built_typo_domains(keywords):
    '''Main function using the input keywords and a list of common tlds'''
    print_info("Building typos...")
    wordlist_path = "wordlist.txt"
    with open ('wordlists/tlds.txt', 'r', encoding='utf-8') as g:
        domains = []
        tlds = g.readlines()
        with open(wordlist_path, 'w', encoding='utf-8') as f:
            for keyword in keywords:
                if '.' in keyword: #we remove the tlds to get keywords to mess up with
                    keyword = '.'.join(keyword.split('.')[:-1])
                    tlds.append(keyword.split('.')[-1])
                domains += generate_typos(keyword)
            for tld in tlds:
                for domi in domains:
                    f.writelines(domi+tld)
                for key_in in keywords:
                    f.write(key_in+ tld)
    return wordlist_path
