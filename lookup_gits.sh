#!/bin/bash
# This program fetchs all endpoints of a public git 
# @authors ybeattie

help()
{
    echo "Usage: lookup_gits.sh [ -u | --git-url ]
               [ -d | --domain ]
               [ -h | --help  ]"
    exit 2
}


VALID_ARGUMENTS=$# # Returns the count of arguments that are in short or long options

if [ "$VALID_ARGUMENTS" -ne 4 ]; then
  help
fi

SHORT=u:,d:,h
LONG=git-url:,domain:,help
OPTS=$(getopt -a -n weather --options $SHORT --longoptions $LONG -- "$@")

eval set -- "$OPTS"

while :
do
  case "$1" in
    -u | --git-url )
      git_url="$2"
      shift 2
      ;;
    -d | --domain )
      domain="$2"
      shift 2
      ;;
    -h | --help)
      help
      ;;
    --)
      shift;
      break
      ;;
    *)
      echo "Unexpected option: $1"
      help
      ;;
  esac
done

source_path=$(echo $PWD)
echo $source_path


dir="/tmp/check_enpoint_${domain}_$(date +%s)"
echo "Saving process logs and info in "$dir 
mkdir $dir >> tmp.log

if [[ $? != 0 ]]; then
    echo "mkdir broken. Are you sure there's no typo in the input domain ?"
    exit 1
fi

cd $dir >> tmp.log

if [[ $? != 0 ]]; then
    echo "cd broken"
    exit 1
fi

git clone $git_url >> tmp.log

if [[ $? != 0 ]]; then
    echo "git source not found"
    exit 1
fi

cd */
tree -f -i | sed -s "s/\.\//${domain}\//g"  > endpoint.list

ehco "There is $(wc -l endpoint.list) to open"
python3 $source_path/open_ip_in_browser.py -f endpoint.list


rm -r $dir




