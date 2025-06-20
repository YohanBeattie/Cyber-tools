#!/bin/bash
if command -v apt &> /dev/null; then
   sudo apt install feroxbuster nmap wafw00f python3 python3-venv tree sslscan
elif command -v yay &> /dev/null; then
    yay -Syu --noconfirm feroxbuster nmap wafw00f python3 python3-venv tree sslscan
else
    echo "Votre gestionnaire de paquet n'est pas géré. Veuillez installer feroxbuster nmap wafw00f python3 python3-venv tree sslscan"
    exit 1
fi


python3 -m venv .venv_cyber_tools
source ./.venv_cyber_tools/bin/activate
python3 -m pip install -r requirements.txt
mkdir tmp
