#!/bin/bash
sudo apt install feroxbuster nmap wafw00f python3

python3 -m venv venv
source ./venv/bin/activate
python3 -m pip install -r requirements.txt
