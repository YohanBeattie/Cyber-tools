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
echo $OPTS

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

echo "git_url=${git_url}"
echo "domain=${domain}"