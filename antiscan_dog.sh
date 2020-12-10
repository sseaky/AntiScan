#!/usr/bin/env bash
# @Author: Seaky
# @Date:   2020/11/30 19:43

##########
# config #
##########

VERSION=20201210

DEBUG=false

PROJECT_NAME="antiscan"
PROJECT_DIR=/tmp/.${PROJECT_NAME}
LOG_DIR="/var/log"
LOG_FILE=${LOG_DIR}/${PROJECT_NAME}.log

LASTSTAMP_FILE=${PROJECT_DIR}/laststamp
THREAT_FILE=${PROJECT_DIR}/threat.csv
FLAG_THREAT_FILE=${PROJECT_DIR}/flag_threat
TRUST_FILE=${PROJECT_DIR}/trust.csv
FLAG_TRUST_FILE=${PROJECT_DIR}/flag_trust
IPSET_SAVE_FILE=${PROJECT_DIR}/ipset.save

INCRON_TABLE="/var/spool/incron/root"

# 每次读入日志行数，倒数
READ_LINE=10

# 统计列表保存时长
DETAIL_HISTORY=$(( 3600 * 24 * 90))

## ipset超时
TIMEOUT_THREAT=$(( 3600 * 24 * 1 ))
TIMEOUT_TRUST=$(( 3600 * 24 * 30 ))


######
# do #
######

check_root(){
    if [ "$EUID" -ne 0 ]; then
        echo "This script must be run as root!" 1>&2
        exit 1
    fi
}

[ -d "$PROJECT_DIR" ] || mkdir $PROJECT_DIR
[ -f "$LASTSTAMP_FILE" ] || touch $LASTSTAMP_FILE


analyse(){
    $DEBUG && echo --function ${FUNCNAME[0]}--
    if [ ! -s "$LOG_FILE" ]; then exit; fi

    $DEBUG && laststamp=0 || read laststamp <<< `head -n 1 $LASTSTAMP_FILE`

    tail -n $READ_LINE $LOG_FILE |
        sed -r 's/([0-9]{10,10})\s+(\S+).*antiscan_([^ :]+).*?SRC=(\S+).*?PROTO=(\S+)(.*)/\1 \2 \3 \4 \5 \6/g' |
        awk -v lslf=$LASTSTAMP_FILE -v ltst=$laststamp -v pn=$PROJECT_NAME \
            -v thf=$THREAT_FILE -v fthf=$FLAG_THREAT_FILE -v trf=$TRUST_FILE -v ftrf=$FLAG_TRUST_FILE \
            -v tmthreat=$TIMEOUT_THREAT -v tmtrust=$TIMEOUT_TRUST \
            -v isf=$IPSET_SAVE_FILE \
            -v debug=`$DEBUG && echo 1 || echo 0` \
'
BEGIN {
}
/.+/{
if(debug){print $0};
unixstamp=$1;datetime=$2;catalog=$3;ip=$4;proto=$5;misc=$6;
if (unixstamp>ltst)
    {
    if(catalog=="trust")
        {trust_objs[ip",ip"]=ip;trust_objs[ip",count"]+=1; trust_objs[ip",unixstamp"]=unixstamp;trust_objs[ip",datetime"]=datetime;
        trust_ips[ip]=1;
        change["trust"]+=1;
        }
    else if(catalog=="threat")
        {threat_objs[ip",ip"]=ip; threat_objs[ip",count"]+=1; threat_objs[ip",unixstamp"]=unixstamp;
        threat_objs[ip",datetime"]=datetime;
        threat_ips[ip]=1;
        cmd="echo "$7" | sed s/DPT=//gI"; cmd | getline port; close(cmd);
        threat_objs[ip",port"]=threat_objs[ip",port"]" "port;
        change["threat"]+=1;
        }
    }
}
END{
if(debug){print "  --threat--"};
for(ip in threat_ips)
    {
    if(debug){print ip};
    system("ipset add --exist "pn"_threat "ip" timeout "tmthreat);
    cmd="echo "threat_objs[ip",port"]" | tr \" \" \"\\n\" | sort -n | uniq | xargs ";
    cmd | getline ports;
    threat_objs[ip",port"]=ports;
    system("echo "ip","threat_objs[ip",count"]","threat_objs[ip",datetime"]","threat_objs[ip",unixstamp"]","ports" >> "thf)
    }
if(debug){print "  --trust--"};
for(ip in trust_ips)
    {
    if(debug){print ip};
    system("ipset add --exist "pn"_trust "ip" timeout "tmtrust);
    system("ipset del -q "pn"_threat "ip);
    system("echo "ip","trust_objs[ip",count"]","trust_objs[ip",datetime"]","trust_objs[ip",unixstamp"]",0 >> "trf)
    }
if(!debug){
    system("echo "unixstamp" > "lslf);
    }
if (change["threat"]>0){system("touch "fthf)}
if (change["trust"]>0){system("touch "ftrf)}
if (change["trust"]+change["threat"] > 0){system("ipset -q save > "isf)}
if(debug){
    print "change_trust:"change["trust"]", change_threat:"change["threat"];
}
}
'
}

merge(){
    $DEBUG && echo --function ${FUNCNAME[0]}--

    now_stamp=`date +%s`

    if [ -f "$FLAG_TRUST_FILE" -a -f "$TRUST_FILE" ]
    then
        cat "$TRUST_FILE" |
            awk -F "," -v ns=$now_stamp -v dh=$DETAIL_HISTORY \
                -v trf=$TRUST_FILE -v ftrf=$FLAG_TRUST_FILE \
                -v debug=`$DEBUG && echo 1 || echo 0` \
'
BEGIN{
if(debug){print "  --trust file--"};
}
/^[0-9]+/{
if(debug){print $0};
    ip=$1;count=$2;datetime=$3;unixstamp=$4;port=$5;
    trust_ips[ip]=1;
    trust_objs[ip",ip"]=ip; trust_objs[ip",count"]+=count; trust_objs[ip",unixstamp"]=unixstamp;
    trust_objs[ip",datetime"]=datetime; ports=0;
}
END{
system("echo ip,count,datetime,unixstamp,port > "trf)
for (ip in trust_ips)
    {
    if (ns - trust_objs[ip",unixstamp"] < dh)
        system("echo "ip","trust_objs[ip",count"]","trust_objs[ip",datetime"]","trust_objs[ip",unixstamp"]","ports" >> "trf)
    }
}
'
        $DEBUG || rm $FLAG_TRUST_FILE
    fi

    if [ -f "$FLAG_THREAT_FILE" -a -f "$THREAT_FILE" ]
    then
        cat "$THREAT_FILE" |
            awk -F "," -v ns=$now_stamp -v dh=$DETAIL_HISTORY \
                -v thf=$THREAT_FILE -v fthf=$FLAG_THREAT_FILE \
                -v debug=`$DEBUG && echo 1 || echo 0` \
'
BEGIN{
if(debug){print "  --threat file--"};
}
/^[0-9]+/{
if(debug){print $0};
    ip=$1;count=$2;datetime=$3;unixstamp=$4;port=$5;
    threat_ips[ip]=1;
    threat_objs[ip",ip"]=ip; threat_objs[ip",count"]+=count; threat_objs[ip",unixstamp"]=unixstamp;
        threat_objs[ip",datetime"]=datetime;
        threat_objs[ip",port"]=threat_objs[ip",port"]" "port;
}
END{
system("echo ip,count,datetime,unixstamp,port > "thf)
for (ip in threat_ips)
    {
    cmd="echo "threat_objs[ip",port"]" | tr \" \" \"\\n\" | sort -n | uniq | xargs ";
    cmd | getline ports;
    threat_objs[ip",port"]=ports;
    if (ns - threat_objs[ip",unixstamp"] < dh)
        system("echo "ip","threat_objs[ip",count"]","threat_objs[ip",datetime"]","threat_objs[ip",unixstamp"]","ports" >> "thf)
    }
}
'
        $DEBUG || rm $FLAG_THREAT_FILE
    fi

}

show_usage(){
    echo
    echo "Usage:"
    echo "  -d    Debug mode"
    echo "  -r    Run"
    echo "  -s    Show statistic"
    echo "  -f    Log file. default ${LOG_FILE}"
    echo "  -x    remove trust ip"
    echo "  -y    remove threat ip"
    echo
    echo "Tips:"
    echo "  Comment/uncomment the item in root's incrontab to disable/enable the trigger:"
    echo "    sudo incrontab -e"
    echo
    echo "  Alter iptables to customize sensible ports "
    echo "    sudo iptables -nvL --line-number "
    echo
    echo "  Alter ipset to customize trust/threat list "
    echo "    sudo ipset list "
    echo
}

remove_ip(){
    [ "$1" = "trust" ] && fn=$TRUST_FILE || fn=$THREAT_FILE
    ipset -q del ${PROJECT_NAME}_$1 $2
    sed -i "/^$2.*$/d" $fn
    ipset -q save > $IPSET_SAVE_FILE
}

show_stat(){
    if [ -f $THREAT_FILE ]
    then
        echo --threat--
        cat $THREAT_FILE
    fi
    if [ -f $TRUST_FILE ]
    then
        echo --trust--
        cat $TRUST_FILE
    fi
}

main(){
    check_root
    analyse
    merge
}

FLAG_RUN=false
while getopts 'df:hrsx:y:' opt
do
    case $opt in
        d) DEBUG=true ;;
        f) logfile=$OPTARG ;;
        r) FLAG_RUN=true ;;
        s) show_stat; exit ;;
        x) remove_ip trust $OPTARG; exit ;;
        y) remove_ip threat $OPTARG; exit ;;
        *) show_usage; exit ;;
    esac
done

[ -n "$logfile" ] && LOG_FILE=$logfile

$FLAG_RUN && main || show_usage


