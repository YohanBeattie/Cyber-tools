#! /bin/bash
# This script launch postgreslql and then create or go to the right workspace

sudo systemctl start postgresql
msfdb init
msfconsole -x "db_status; workspace -a $1"
