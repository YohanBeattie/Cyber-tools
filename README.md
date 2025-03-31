# Cyber-tools
Cybersecurity tools

## Table des matières

- 🪧 [About](#about)
- 🚀 [Installation](#installation)
- 📖 [Utilisation](#utilisation)
- 🛠️ [Troubleshooting](#troubleshooting)

## About

This project is made to help pentesters or developer that wish to assess there security level. 

## Installation 
```
chmod +x install.sh
./install.sh
source ./venv/bin/activate
```
### Using other UNIX OS than Kali

If you are not using Kali Linux, feroxbuster will not be install by the script and you may need to install it manually : 
```
curl -sLO https://github.com/epi052/feroxbuster/releases/latest/download/feroxbuster_amd64.deb.zip
unzip feroxbuster_amd64.deb.zip
sudo apt install ./feroxbuster_*_amd64.deb
```

## Utilisation
### Basic checks

Basic-checks performs a few tests on the scope given such as checking the WAF, the SSL/TLS configuration and also performs a nmap scan and starts some fuzzing. 
This scan should be made from the IP given to your target : before you run it, be sure to insert your IP (l.137) or you can also use the --force option to bypass that check. You can then run :
 ```
echo 'exemple.com' > scope.txt
echo '127.0.0.1' >> scope.txt
./venv/bin/python basic_checks.py -f scope.txt
```

### Generate Cookie with CSRF

This program is usefull to gather a list of valid cookie on a login form protected wiht single-use CSRF token. This script must be adapted to you case by probably getting your hands dirty.

### Homemade Password Generator

This script is made to generate a specific bunch of password based on some password. This script must be adapted to the usecase. Please edit line 23 to 26 and then run :
```
python3 home_passwd_gen.py -o mycompany_pwd.dict
```

### Open IP in browser

A simple script opening all ips in browser on http and https page. The file can contain either IPs or IP:Port. Pages are open by group of 20 :
```
python3 ./open_ip_in_browser.py -f ips.txt
```

## Troubleshooting

Most of those scripts were tested on Kali Linux and Debian. Any other OS might cause some distress. Feel free to create an issue if so.

### Issues with feroxbuster 
While being easy to install on Kali (apt install feroxbuster), on other OS you need to run the following lines :
```
curl -sLO https://github.com/epi052/feroxbuster/releases/latest/download/feroxbuster_amd64.deb.zip
unzip feroxbuster_amd64.deb.zip
sudo apt install ./feroxbuster_*_amd64.deb
```
Moreover you need to have clone the Seclists repo in /usr/share/wordlists (be sure to check the typo SecLists and Seclists) before being able to run the command.



