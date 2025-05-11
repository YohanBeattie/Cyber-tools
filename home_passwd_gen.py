#!/bin/python3
'''
This program creates a custom password dictionnary
@authors ybeattie
'''

import itertools
import argparse

def parse():
    '''Parser for output argument'''
    parser = argparse.ArgumentParser(
        prog="home_passwd_gen",
        description="Creates a password of dictionnary based on some input words",
    )
    parser.add_argument("-o", "--output", help="Output file",
        default='output_passwd.dict', required=False)
    return parser.parse_args()

def replacer(letter, char, word, start):
    ''' Recursive function to replace a charcter by a similar one'''
    for rang in range(start, len(word)):
        if word[rang] == letter:
            return replacer(letter, char, word[:rang]+word[rang:].replace(letter, char, 1), rang+1)\
                        +replacer(letter, char, word, rang+1)
    return [word]

def main():
    '''Main function building the dictionnary'''
    args = parse()
    ####################################################################
    #Insert a sample of words in the above lists
    #It is advise to let a empty string in each list
    words1 = ['Mon','Entreprise','']
    words2 = [ 'group', 'GROUP','']
    date = ['2022', '2023', '2024', '2025']
    spe_char = ['$', '!', '&', '=', '#', '_', '$', '']
    ######################################################################
    passwd_little = []
    print('Launching permutations')
    for element in list(itertools.permutations(spe_char, 2)):
        for word1 in words1:
            for word2 in words2:
                new_words = [word1+word2] + ['randomezafjpemdjs']

                passwd_little += [''.join(list(mypermut))
                    for mypermut in list(itertools.permutations(new_words))]
                new_words+= list(element)

                passwd_little += [''.join(list(mypermut))
                    for mypermut in list(itertools.permutations(new_words))]

    #print(passwd_no_date[0:10])
    passwd = passwd_little
    print('Launching character replacement on '+str(len(passwd_little))+' passwords')
    with open(args.output, 'w', encoding='utf-8') as g:
        for password in passwd_little:
            #print(str(i) + '/'+str(len(passwd)))
            if 'randomezafjpemdjs' in password:
                for year in date:
                    passwd.append(password.replace('randomezafjpemdjs', year))
            for passwd_iterator in replacer('a', '@', password, 0):
                if passwd_iterator != password:
                    g.write(passwd_iterator+'\n')
            for passwd_iterator in replacer('o', '0', password, 0):
                if passwd_iterator != password:
                    g.write(passwd_iterator+'\n')
            for passwd_iterator in replacer('O', '0', password, 0):
                if passwd_iterator != password:
                    g.write(passwd_iterator+'\n')
            for passwd_iterator in replacer('A', '@', password, 0):
                if passwd_iterator != password:
                    g.write(passwd_iterator+'\n')
            for passwd_iterator in replacer('A', '4', password, 0):
                if passwd_iterator != password:
                    g.write(passwd_iterator+'\n')
            for passwd_iterator in replacer('l', '1', password, 0):
                if passwd_iterator != password:
                    g.write(passwd_iterator+'\n')
            for passwd_iterator in replacer('s', '$', password, 0):
                if passwd_iterator != password:
                    g.write(passwd_iterator+'\n')
            for passwd_iterator in replacer('S', '$', password, 0):
                if passwd_iterator != password:
                    g.write(passwd_iterator+'\n')
    print('Launching writting output')

    with open(args.output, 'a', encoding='utf-8') as g:
        for password in passwd:
            g.write(password+'\n')
    print(f'File was created : {args.output}')
    print('END')

if __name__=='__main__':
    main()
