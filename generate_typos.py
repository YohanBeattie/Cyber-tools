from tld import get_tld
from tld.exceptions import TldDomainNotFound
from utils import printInfo

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
    alternatives = {'s': '5', 'l': '1', 'o': '0', 'a': '4', 'e': '3', 'i': '1', 't': '7', '@':'a', '!':'1'}
    for i, c in enumerate(name):
        if c.lower() in alternatives:
            typos.append(name[:i] + alternatives[c.lower()] + name[i+1:])
    
    # Add the TLD back
    if tld:
        return [f"{typo}.{tld}" for typo in set(typos)]
    else:
        return list(set(typos))
    
def builtTypoDoms(keywords):
    printInfo("Building typos...")
    wordlist_path = "wordlist.txt"
    with open ('wordlists/tlds.txt', 'r', encoding='utf-8') as g:
        domains = []
        with open(wordlist_path, 'w', encoding='utf-8') as f:
            for keyword in keywords:
                domains += generate_typos(keyword)
            for tld in g.readlines():
                for domi in domains:
                    f.writelines(domi+tld)
                for key_in in keywords:
                    f.write(key_in+ tld)
                
            
    return wordlist_path