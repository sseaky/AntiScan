#!/usr/bin/env bash
# @Author: Seaky
# @Date:   2022/1/28 16:20

HEAD_COUNT=50
FAIL_COUNT=10
WHITELIST=''
LOG_GEO=true
DEBUG=false

prelist=`cat /etc/hosts.deny | egrep -v '^\s*$' | egrep -v '^#' | cut -d":" -f 2 | xargs`
succ_ips=`last | head -n $HEAD_COUNT |  awk '/^[^ ]+.*pts/{print $3}' | sort | uniq | xargs`

fail_ips=`lastb | head -n $HEAD_COUNT |  awk '/^[^ ]+.*ssh:notty/{print $3}' |
 sort | uniq -c | sort -r |
  awk -v th=$FAIL_COUNT '{if($1>th){print $2}}' | xargs`

for ip in $fail_ips
do
  if [[ " ${WHITELIST[*]} " =~ " ${ip} " ]] ; then 
    $DEBUG && echo "$ip in whitelist"
    continue
  fi
  if [[ " ${succ_ips[*]} " =~ " ${ip} " ]] ; then 
    $DEBUG && echo "$ip has login successfully before"
    continue
  fi
  if [[ ! " ${prelist[*]} " =~ " ${ip} " ]] ; then 
    if $LOG_GEO ; then
      if [ -n "`which jq`" ] ; then
        a=`curl --silent https://api.ip.sb/geoip/$ip`
        geo="| "`echo $a | jq .country`.`echo $a | jq .region`.`echo $a | jq .city`
      else
        echo "Install jq first"
      fi
    fi
    cmd="echo -e \"ALL:${ip}:deny    # `date` ${geo//\"/}\" >> /etc/hosts.deny"
    $DEBUG && echo $cmd
    eval $cmd
  else
    $DEBUG && echo "$ip is in ban list"
  fi
done
