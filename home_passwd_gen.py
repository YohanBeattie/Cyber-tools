#! /bin/python3
import itertools
import argparse

def parse():
    parser = argparse.ArgumentParser(
        prog="Creates a password of dictionnary based on some input words",
        description="This script creates all permutation of given words and more",
    )
    parser.add_argument("-o", "--output", help="Output file", default='output_passwd.dict', required=False)
    return parser.parse_args()

def replacer(letter, char, word, start):
    for rang in range(start, len(word)):
        if word[rang] == letter:
            return replacer(letter, char, word[:rang]+word[rang:].replace(letter, char, 1), rang+1)+replacer(letter, char, word, rang+1)
    return [word]

def main():
    args = parse()
    words1 = ['HMP', 'HeadMind', 'HEADMIND', 'headmind', 'HEADMIND', 'Headmind']  
    words2 = ['']
    date = ['2020', '2021', '2022', '2023', '2024', '']
    spe_char = ['$', '!', '?', '%', '&', '=', '#', '_', '']
    passwd_little = []
    print('Launching permutations')
    for element in list(itertools.permutations(spe_char, 2)):
        for word1 in words1:
            for word2 in words2:
                new_words = [word1] + [word2] + ['2019']
                passwd_little += [''.join(list(mypermut)) for mypermut in list(itertools.permutations(new_words))]
                new_words+= list(element)
                passwd_little += [''.join(list(mypermut)) for mypermut in list(itertools.permutations(new_words))]

    #print(passwd_no_date[0:10])
    passwd = passwd_little
    print('Launching character replacement')
    for password in passwd_little:
        if '2019' in password:
            for year in date:
                passwd.append(password.replace('2019', year))
        for passwd_iterator in replacer('a', '@', password, 0):
            if passwd_iterator != password:
                passwd.append(passwd_iterator)
        for passwd_iteraotr in replacer('o', '0', password, 0):
            if passwd_iterator != password:
                passwd.append(passwd_iterator)
        for passwd_iteraotr in replacer('O', '0', password, 0):
            if passwd_iterator != password:
                passwd.append(passwd_iterator)
        for passwd_iteraotr in replacer('A', '@', password, 0):
            if passwd_iterator != password:
                passwd.append(passwd_iterator)
        for passwd_iteraotr in replacer('A', '4', password, 0):
            if passwd_iterator != password:
                passwd.append(passwd_iterator)
        for passwd_iteraotr in replacer('l', '1', password, 0):
            if passwd_iterator != password:
                passwd.append(passwd_iterator)
    print('Launching writting output')

    with open(args.output, 'w', encoding='utf-8') as g:
        for password in passwd:
            g.write(password+'\n')
    print('DONE')

if __name__=='__main__':
    main()

        


