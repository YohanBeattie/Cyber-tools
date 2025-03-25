# This script launch postgreslql and then create or go to the right workspace

#if [ "$(id -u)" != "0" ]; then
#    echo "You must be root to do this." 1>&2
#    exit 100
#fi
#if [ "$#" != "1" ]; then
#    echo "Please enter the name of the mission in parameter"
#    exit 100
#fi

sudo systemctl start postgresql
msfdb init
msfconsole -x "db_status; workspace -a $1"

