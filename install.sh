#!/bin/bash
sudo apt install feroxbuster nmap wafw00f python3 python3-venv tree sslscan

python3 -m venv .venv_cyber_tools
source ./.venv_cyber_tools/bin/activate
python3 -m pip install -r requirements.txt
