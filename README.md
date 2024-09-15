# Cyber-tools
Cybersecurity tools

## Table des matières

- 🪧 [About](#about)
- 🚀 [Installation](#installation)
- 🛠️ [Utilisation](#utilisation)

## About

This project is made to help pentesters or developer that wish to assess there security level. 

## Installation 
```
python3 -m pip install -r requirements.txt
```

## Utilisation
### Basic checks

Basic-checks performs a few tests on the scope given such as checking the WAF, the SSL/TLS configuration and also performs a nmap scan. Before you run it, be sure to modify you IP (l.137) or you can also use the --force option to bypass that check. You can then run :
 ```
echo 'exemple.com' > scope.txt
echo '127.0.0.1' >> scope.txt
python3 basic_checks.py -f scope.txt
```

### Generate Cookie with CSRF

This program must be adapted to you case by probably getting your hands dirty but when well configured, this script loads the connexion page and then performs a legit connexion using the credentials provided and the csrf token gathered

### Home Password Generator

This script is made to generate a specific bunch of password based on some password. This script must be adapted to the usecase. Please edit line 23 to 26 and then run :
```
python3 home_passwd_gen.py -o mycompany_pwd.dict
```

### Open IP in browser

A simple script opening all ips in browser on http and https page. The file can contain either IPs or IP:Port. Pages are open by group of 20 :
```
python3 ./open_ip_in_browser.py -f ips.txt
```
