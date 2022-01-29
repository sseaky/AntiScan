#!/usr/bin/env bash
# @Author: Seaky
# @Date:   2022/1/28 16:20

HEAD_COUNT=50
FAIL_COUNT=10
WHITELIST=''
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
    cmd="echo \"ALL:${ip}:deny  # `date`\" >> /etc/hosts.deny"
    $DEBUG && echo $cmd
    eval $cmd
  else
    $DEBUG && echo "$ip is in ban list"
  fi
done
